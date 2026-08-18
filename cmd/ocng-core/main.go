// Command ocng-core is the assembled core binary (increment 5.5, ASSEMBLY-5.5
// §1, config surface consolidated by T5): one process serving what
// increments 1–5 proved, behind a real net/http listener. It adds NO
// capability — it wires the existing handlers (engine, ingest, search,
// /admin-ng read+write surface, /ocng/version, serve) and runs the
// orchestrator loop. 1–2 replicas per ADR-009; migration is serialised by
// the shared advisory lock, so concurrent replica startup is a supported
// path.
//
// Configuration is env vars in the deployment definitions (ADR-009 — no
// config file; deploy/CONFIG.md is the operator reference). T5: the whole
// surface validates in ONE pass before anything connects — every missing
// and invalid var is reported in one exit message, parse errors are fatal
// (F-1), and after validation the boot report names every dev-grade
// posture in effect (F-2).
//
//	OCNG_DB_URL             postgres URL (required)
//	OCNG_CAS_ENDPOINT       S3 endpoint host:port (required)
//	OCNG_CAS_KEY/SECRET     S3 credentials (required)
//	OCNG_CAS_BUCKET         CAS bucket (required)
//	OCNG_LISTEN             listen address (default :8085)
//	OCNG_SERVE_DB_URL       postgres URL for the serve handler's dedicated
//	                        pool, connecting as the least-privilege
//	                        ocng_serve role (T2: SELECT on exactly the
//	                        serve-read set). Unset = serve shares the
//	                        general pool and the structural enforcement is
//	                        OFF — boots (the dev on-ramp) but the boot
//	                        report names it as a DISABLED T2 BOUNDARY.
//	OCNG_SERVE_DB_PASSWORD  password EnsureRole gives ocng_serve when it
//	                        first creates it (default ocng_serve — dev
//	                        grade; production sets its own)
//	OCNG_DEFINITIONS_DIR    directory of YAML workflow definitions — the
//	                        ADR-009 authoring surface: bind mount authors,
//	                        database executes (internal/definitions). The
//	                        loader polls it and upserts changed files with a
//	                        content hash; execution reads the DB, so a
//	                        replica without the mount still runs what the
//	                        database holds. Optional; with neither the dir
//	                        nor DB rows, no workflow can start. Replaces the
//	                        assembly-era OCNG_DEFINITIONS_FILE JSON stand-in.
//	OCNG_DEV_AUTH           "1" enables the dev auth seam (X-Roles principals
//	                        + Basic /ingest credentials). DEFAULT OFF: the
//	                        binary closes the seam itself rather than trusting
//	                        deployment discipline (ADR-012; T1 step 1).
//	OCNG_INGEST_USER/PASS   dev-seam credentials for /ingest (default
//	                        admin/opencast; only honoured under OCNG_DEV_AUTH)
//	OCNG_OIDC_ISSUER        the ONE operated OIDC issuer (ADR-002). When set,
//	                        Authorization: Bearer tokens validate against it.
//	OCNG_OIDC_CLIENT_ID     the audience ocng requires (required with issuer)
//	OCNG_OIDC_ROLES_CLAIM   claim path carrying the role array (default
//	                        "roles"; dotted paths descend)
//	OCNG_LTI_PLATFORMS_FILE JSON array of LTI 1.3 platform registrations.
//	                        Without it /lti is not mounted.
//	OCNG_LTI_SESSION_SECRET required (>=32 bytes) when platforms are
//	                        registered; shared across replicas, never
//	                        generated.
//	OCNG_GC_GRACE/INTERVAL  the T4 CAS collector — OFF by default, opt-in.
//	                        The enablement gate is satisfied (mid-migration-
//	                        transient fixture, 2026-08-18); sizing rules in
//	                        deploy/CONFIG.md. Both-or-nothing; bad or
//	                        non-positive durations are fatal.
//
// Operational constants that are deliberately NOT configurable (T5: no new
// configurability): engine lease 60 s, MaxAttempts 3, orchestrator tick
// 500 ms, definitions poll 2 s.
//
// Route table (the edge contract, ADR-012 — expressible as Ingress rules):
//
//	/ocng/version                → coreinfo
//	/elements/, /publications/   → serve
//	/ingest/                     → ingest
//	/search/, /api/              → searchapi
//	/admin-ng/resources/         → searchapi (boot-support enumerations)
//	/admin-ng/, /info/           → adminapi
//	/play/                       → watchpage (the Paella datapass shell)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/acl"
	"ocng/internal/adminapi"
	"ocng/internal/authn"
	"ocng/internal/cas"
	"ocng/internal/config"
	"ocng/internal/coreinfo"
	"ocng/internal/definitions"
	"ocng/internal/engine"
	"ocng/internal/gc"
	"ocng/internal/ingest"
	"ocng/internal/jose"
	"ocng/internal/lti"
	"ocng/internal/mediapackage"
	"ocng/internal/oidcauth"
	"ocng/internal/ops"
	"ocng/internal/provision"
	"ocng/internal/search"
	"ocng/internal/searchapi"
	"ocng/internal/serve"
	"ocng/internal/serveset"
	"ocng/internal/watchpage"
)

// coreConfig is everything run() needs, produced by ONE validation pass
// (T5 step 2) before any connection is attempted — so a misconfigured core
// exits with the full list of problems without needing its database up.
type coreConfig struct {
	dbURL                  string
	casEndpoint, casKey    string
	casSecret, casBucket   string
	listen                 string
	serveDBURL             string // "" = enforcement OFF (dev on-ramp)
	servePassword          string
	servePasswordDefault   bool
	definitionsDir         string
	devAuth                bool
	ingestUser, ingestPass string
	oidcIssuer             string
	oidcClientID           string
	oidcRolesClaim         string
	ltiPlatforms           []lti.Platform
	ltiSessionSecret       string
	gcGrace, gcInterval    time.Duration
	gcEnabled              bool
}

const serveDevPassword = "ocng_serve"

// loadConfig is the T5 single validation pass: every problem on the surface
// is collected and reported in one exit message (config.Set), including the
// conditional requires (OIDC client id with issuer; LTI session secret with
// registered platforms, >=32 bytes) with their exact pre-T5 semantics.
func loadConfig() (coreConfig, error) {
	var s config.Set
	var c coreConfig

	c.dbURL = s.Require("OCNG_DB_URL")
	c.casEndpoint = s.Require("OCNG_CAS_ENDPOINT")
	c.casKey = s.Require("OCNG_CAS_KEY")
	c.casSecret = s.Require("OCNG_CAS_SECRET")
	c.casBucket = s.Require("OCNG_CAS_BUCKET")
	c.listen = s.String("OCNG_LISTEN", ":8085")

	c.serveDBURL, _ = s.Raw("OCNG_SERVE_DB_URL")
	c.servePassword = s.String("OCNG_SERVE_DB_PASSWORD", serveDevPassword)
	c.servePasswordDefault = c.servePassword == serveDevPassword

	c.definitionsDir, _ = s.Raw("OCNG_DEFINITIONS_DIR")
	if v, set := s.Raw("OCNG_DEFINITIONS_FILE"); set && v != "" {
		// the JSON stand-in is retired, not silently ignored: a deployment
		// still setting it would otherwise run with no definitions at all
		s.Errf("OCNG_DEFINITIONS_FILE was replaced by OCNG_DEFINITIONS_DIR (a directory of YAML files — deploy/CONFIG.md \"Workflow definitions\")")
	}

	c.devAuth = s.String("OCNG_DEV_AUTH", "") == "1"
	c.ingestUser = s.String("OCNG_INGEST_USER", "admin")
	c.ingestPass = s.String("OCNG_INGEST_PASS", "opencast")

	c.oidcIssuer, _ = s.Raw("OCNG_OIDC_ISSUER")
	if c.oidcIssuer != "" {
		c.oidcClientID = s.Require("OCNG_OIDC_CLIENT_ID")
	}
	c.oidcRolesClaim = s.String("OCNG_OIDC_ROLES_CLAIM", "roles")

	// LTI trust data loads inside the validation pass so a bad platforms
	// file or missing session secret joins the one exit message.
	if path, set := s.Raw("OCNG_LTI_PLATFORMS_FILE"); set {
		platforms, err := loadLTIPlatforms(path)
		if err != nil {
			s.Errf("OCNG_LTI_PLATFORMS_FILE: %v", err)
		}
		c.ltiPlatforms = platforms
		if len(platforms) > 0 {
			// Every replica must share the secret (login, launch and
			// delivery may hit different processes — ADR-009), so it is
			// config, not generated.
			c.ltiSessionSecret = s.Require("OCNG_LTI_SESSION_SECRET")
			if c.ltiSessionSecret != "" && len(c.ltiSessionSecret) < 32 {
				s.Errf("OCNG_LTI_SESSION_SECRET must be at least 32 bytes (got %d)", len(c.ltiSessionSecret))
			}
		}
	}

	// T4 GC gate: OFF unless BOTH knobs are set. The gate's precondition —
	// the mid-migration-transient fixture — exists and passes, so an
	// operator MAY enable sweeping; deploy/CONFIG.md carries the sizing
	// rules. Durations validate here so a typo is fatal, not silently
	// half-enabled. A non-positive grace is fatal too: the fixture's
	// counterfactual proves grace is the ONLY thing protecting a
	// mid-migration put-before-reference object, so grace 0 means every
	// freshly-put object is reclaimable on the next sweep tick.
	grace, graceSet := s.Duration("OCNG_GC_GRACE")
	interval, intervalSet := s.Duration("OCNG_GC_INTERVAL")
	c.gcGrace, c.gcInterval = grace, interval
	c.gcEnabled = graceSet && intervalSet
	if graceSet && grace <= 0 {
		s.Errf("OCNG_GC_GRACE must be positive (got %v): grace is the only protection for freshly-put, not-yet-referenced CAS objects", grace)
	}
	if intervalSet && interval <= 0 {
		s.Errf("OCNG_GC_INTERVAL must be positive (got %v)", interval)
	}

	return c, s.Err()
}

func loadLTIPlatforms(path string) ([]lti.Platform, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var platforms []lti.Platform
	if err := json.Unmarshal(raw, &platforms); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	for _, p := range platforms {
		if p.Issuer == "" || p.ClientID == "" || p.JWKSURI == "" || p.AuthEndpoint == "" || len(p.DeploymentIDs) == 0 {
			return nil, fmt.Errorf("%s: registration for issuer %q is incomplete — trust data has no optional fields", path, p.Issuer)
		}
	}
	return platforms, nil
}

func run() error {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// The pilot-gate boot report (T5 step 3, F-2): after validation, before
	// anything connects, one unmissable block naming every dev-grade
	// posture — with the disabled T2 boundary called out as a disabled
	// security boundary, not one tuning default among many. Its paper twin
	// is deploy/CONFIG.md's pilot-gate table.
	postures := config.CorePostures{
		ServeEnforcementOff:  cfg.serveDBURL == "",
		ServePasswordDefault: cfg.servePasswordDefault,
		DevAuth:              cfg.devAuth,
		NoIdentityPath:       cfg.oidcIssuer == "" && len(cfg.ltiPlatforms) == 0,
	}
	if rep := postures.BootReport(); rep != "" {
		fmt.Fprintln(os.Stderr, rep)
	} else {
		log.Info(config.AllClear)
	}

	pool, err := pgxpool.New(ctx, cfg.dbURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Migrations are ledger-skipped and advisory-locked (T2): two replicas
	// racing here is a deployment scenario ADR-009 names, not an error.
	for _, mig := range []func(context.Context, *pgxpool.Pool) error{
		engine.Migrate, mediapackage.Migrate, acl.Migrate, search.Migrate,
		lti.Migrate, // the flow store: launch state/nonce shared across replicas
		gc.Migrate,  // the mark-sweep candidate ledger (T4 archive delete)
	} {
		if err := mig(ctx, pool); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	// T2 guard-as-structure: the ocng_serve role (SELECT on exactly the
	// serve-read set — internal/serveset/READSET.md). OCNG_SERVE_DB_URL
	// connects the serve handler's dedicated pool as that role so an
	// out-of-set serve query fails at the database in every environment.
	if err := serveset.EnsureRole(ctx, pool, cfg.servePassword); err != nil {
		return fmt.Errorf("serve role: %w", err)
	}
	servePool := pool
	if cfg.serveDBURL != "" {
		servePool, err = pgxpool.New(ctx, cfg.serveDBURL)
		if err != nil {
			return fmt.Errorf("serve pool: %w", err)
		}
		defer servePool.Close()
		log.Info("serve pool connected as least-privilege role", "role", serveset.Role)
	}
	// (the unset case is carried by the boot report above, not a WARN in
	// the scroll — F-2)

	store, err := cas.New(ctx, cfg.casEndpoint, cfg.casKey, cfg.casSecret, cfg.casBucket)
	if err != nil {
		return fmt.Errorf("cas: %w", err)
	}

	// The ADR-009 definitions mechanism (T5 step 1): the bind mount is the
	// authoring surface, the database is the execution source. Boot load is
	// fail-loud; the runtime watcher keeps last-good on operator typos. The
	// registry is passed to execution surfaces UNCONDITIONALLY — a replica
	// without a mount still executes what the database holds.
	if cfg.definitionsDir != "" {
		loader := &definitions.Loader{Pool: pool, Dir: cfg.definitionsDir, Log: log}
		if err := loader.LoadOnce(ctx); err != nil {
			return err
		}
		go loader.Watch(ctx, 2*time.Second)
	}
	defs := &definitions.Registry{Pool: pool}

	host, _ := os.Hostname()
	inline := engine.NewInlineRunner(pool, fmt.Sprintf("core-%s-pid%d", host, os.Getpid()),
		30*time.Second, map[string]engine.InlineFunc{
			"snapshot":          ops.Snapshot(store),
			"publish-configure": ops.Publish(),
		})
	// The provisioning port (ADR-011 A7 / D-045): this deployment is the VM
	// topology, so the adapter is None — core holds no provisioning
	// credential; the resident lease-worker discovers committed ASSIGNED
	// rows. The K8s Job adapter (provision.KubernetesJob) is shaped but
	// deferred until a real cluster exists to validate it.
	eng := engine.New(pool, provision.None{}, engine.Options{
		Lease:       60 * time.Second,
		MaxAttempts: 3,
		Inline:      inline,
	})

	// The CAS collector (T4 archive delete: reference-drop + GC). OFF unless
	// BOTH knobs are set — reclaiming bytes is an operator decision, and the
	// grace must be sized to the deployment's restore horizon and longest
	// put-then-reference gap (internal/gc package doc; ADR-006: grace >=
	// restore horizon). Sweeps are idempotent and safe across replicas.
	if cfg.gcEnabled {
		go func() {
			tick := time.NewTicker(cfg.gcInterval)
			defer tick.Stop()
			for range tick.C {
				rep, err := gc.Sweep(ctx, pool, store, cfg.gcGrace)
				if err != nil {
					log.Error("gc sweep", "err", err)
					continue
				}
				if rep.Swept > 0 || rep.Candidates > 0 {
					log.Info("gc sweep", "objects", rep.Objects, "referenced", rep.Referenced,
						"candidates", rep.Candidates, "swept", rep.Swept)
				}
			}
		}()
		log.Info("cas gc enabled", "grace", cfg.gcGrace, "interval", cfg.gcInterval)
	} else {
		log.Info("cas gc disabled (the T4 gate — deploy/CONFIG.md pilot-gate table; expected in every current deployment)")
	}

	// The orchestrator loop — what the e2e tests' Step() polling did, now
	// resident. Every mutation inside Step is state-predicate-guarded, so
	// two replicas stepping concurrently is safe (engine INVARIANTS).
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for range tick.C {
			if err := eng.Step(ctx); err != nil {
				log.Error("engine step", "err", err)
			}
		}
	}()

	// ONE extraction layer per process (T1 step 1): every surface resolves
	// principals through the same authenticator. The dev seam defaults OFF —
	// the binary closes it itself (ADR-012); dev/test shapes opt in.
	authCfg := authn.Config{
		DevSeam:      cfg.devAuth,
		ServiceUsers: map[string]string{cfg.ingestUser: cfg.ingestPass},
	}
	if cfg.oidcIssuer != "" {
		authCfg.OIDC = oidcauth.New(oidcauth.Config{
			IssuerURL:  cfg.oidcIssuer,
			ClientID:   cfg.oidcClientID,
			RolesClaim: cfg.oidcRolesClaim,
		})
		log.Info("oidc bearer validation enabled", "issuer", cfg.oidcIssuer)
	}
	var sessions *authn.SessionCodec
	if len(cfg.ltiPlatforms) > 0 {
		sessions = &authn.SessionCodec{Secret: []byte(cfg.ltiSessionSecret)}
		authCfg.Session = sessions
	}
	auth := authn.New(authCfg)

	mux := http.NewServeMux()
	mux.Handle("/ocng/", coreinfo.Handler())
	srvH := serve.Handler(servePool, store, serve.WithAuth(auth))
	mux.Handle("/elements/", srvH)
	mux.Handle("/publications/", srvH)
	mux.Handle("/ingest/", ingest.NewHandler(ingest.Options{
		Pool: pool, Store: store, Engine: eng, Definitions: defs, Auth: auth,
	}))
	searchH := searchapi.NewHandler(pool, searchapi.WithAuth(auth))
	mux.Handle("/search/", searchH)
	mux.Handle("/api/", searchH)
	mux.Handle("/admin-ng/resources/", searchH)
	// T4: the admin write surface shares the ingest surface's store/engine/
	// definitions — create's processing workflow publishes through the same
	// pinned path every other publish uses (D-044)
	adminH := adminapi.Handler(pool, adminapi.WithAuth(auth), adminapi.WithWrite(store, eng, defs))
	mux.Handle("/admin-ng/", adminH) // list routes are the 5.6 merged handlers
	mux.Handle("/info/", adminH)
	// Player increment: the datapass watch page (the manifest's /play/{id}
	// publication URL). Static shell — authorization lives on the data.
	mux.Handle("/play/", watchpage.Handler())

	// LTI 1.3 assertion path (ADR-002 A1): mounted only when platforms are
	// registered — the registry is the trust boundary, and an empty registry
	// means no assertion surface at all.
	if len(cfg.ltiPlatforms) > 0 {
		ltiSvc := &lti.Service{
			Registry: lti.NewRegistry(cfg.ltiPlatforms),
			Store:    &lti.PGFlowStore{Pool: pool},
			Keys:     &jose.Fetcher{},
			OnLaunch: authn.LTISessionOnLaunch(sessions),
		}
		mux.Handle("/lti/", ltiSvc.Handler())
		log.Info("lti assertion path mounted", "platforms", len(cfg.ltiPlatforms))
	}

	log.Info("ocng-core listening", "addr", cfg.listen)
	return http.ListenAndServe(cfg.listen, mux)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ocng-core:", err)
		os.Exit(1)
	}
}
