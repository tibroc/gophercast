// Code-adjacent data, hand-committed: the ADR-011 execution-class table for
// all 98 workflow operations, generated from the S4 measurement
// (archive/analysis/contracts/workflow-operations.csv, execution_class
// column — 33 worker / 61 inline / 4 unclear; the split is verified by
// TestClassTableCounts). The class is a property of the OPERATION, decided
// by ADR-011 — adopters' workflow definitions do not choose it.
//
// ClassUnclear ops fail loudly at dispatch: each of the four depends on an
// unmade design decision (CONTRACTS §3.2) and must not silently run in
// either class.
package engine

type ExecClass int

const (
	ClassUnknown ExecClass = iota // not one of the 98 — fails loudly
	ClassWorker                   // external process / media-scale bytes: one ephemeral container per job
	ClassInline                   // metadata/DB/kilobyte-scale: runs in core, identical task lifecycle
	ClassUnclear                  // one of the 4 undecided ops — refuses to run
)

// ClassOf returns the ADR-011 class for an operation id.
func ClassOf(operation string) ExecClass {
	return opClass[operation]
}

var opClass = map[string]ExecClass{
	"add-catalog":                          ClassInline,
	"amberscript-attach-transcription":     ClassInline,
	"analyze-mediapackage":                 ClassInline,
	"analyze-tracks":                       ClassInline,
	"assert":                               ClassInline,
	"asset-delete":                         ClassInline,
	"attach-watson-transcription":          ClassInline,
	"changetype":                           ClassInline,
	"cleanup":                              ClassInline,
	"comment":                              ClassInline,
	"conditional-config":                   ClassInline,
	"configure-by-dcterm":                  ClassInline,
	"cut-marks-to-smil":                    ClassInline,
	"defaults":                             ClassInline,
	"duplicate-event":                      ClassInline,
	"error-resolution":                     ClassInline,
	"export-wf-properties":                 ClassInline,
	"google-speech-attach-transcription":   ClassInline,
	"hello-world":                          ClassInline,
	"http-notify":                          ClassInline,
	"import-wf-properties":                 ClassInline,
	"incident":                             ClassInline,
	"include":                              ClassInline,
	"log":                                  ClassInline,
	"matrix-notify":                        ClassInline,
	"mattermost-notify":                    ClassInline,
	"metadata-to-acl":                      ClassInline,
	"microsoft-azure-attach-transcription": ClassInline,
	"post-mediapackage":                    ClassInline,
	"probe-resolution":                     ClassInline,
	"publication-channel-to-workspace":     ClassInline,
	"publish-configure":                    ClassInline,
	"publish-configure-aws":                ClassInline,
	"publish-engage":                       ClassInline,
	"publish-engage-aws":                   ClassInline,
	"publish-oaipmh":                       ClassInline,
	"rename-files":                         ClassInline,
	"republish-oaipmh":                     ClassInline,
	"retract-configure":                    ClassInline,
	"retract-configure-aws":                ClassInline,
	"retract-engage":                       ClassInline,
	"retract-engage-aws":                   ClassInline,
	"retract-oaipmh":                       ClassInline,
	"retract-partial":                      ClassInline,
	"retract-partial-aws":                  ClassInline,
	"retract-youtube":                      ClassInline,
	"sanitize-adaptive":                    ClassInline,
	"select-version":                       ClassInline,
	"send-email":                           ClassInline,
	"series":                               ClassInline,
	"snapshot":                             ClassInline,
	"speechtotext-attach":                  ClassInline,
	"start-workflow":                       ClassInline,
	"statistics-writer":                    ClassInline,
	"subtitle-timeshift":                   ClassInline,
	"tag":                                  ClassInline,
	"tag-by-dcterm":                        ClassInline,
	"tag-engage":                           ClassInline,
	"theme":                                ClassInline,
	"transfer-metadata":                    ClassInline,
	"webvtt-to-cutmarks":                   ClassInline,
	"clone":                                ClassUnclear,
	"copy":                                 ClassUnclear,
	"cover-image":                          ClassUnclear,
	"move-storage":                         ClassUnclear,
	"amberscript-start-transcription":      ClassWorker,
	"composite":                            ClassWorker,
	"concat":                               ClassWorker,
	"crop-video":                           ClassWorker,
	"demux":                                ClassWorker,
	"editor":                               ClassWorker,
	"encode":                               ClassWorker,
	"execute-many":                         ClassWorker,
	"execute-once":                         ClassWorker,
	"extract-text":                         ClassWorker,
	"google-speech-start-transcription":    ClassWorker,
	"image":                                ClassWorker,
	"image-convert":                        ClassWorker,
	"image-to-video":                       ClassWorker,
	"ingest-download":                      ClassWorker,
	"inspect":                              ClassWorker,
	"microsoft-azure-start-transcription":  ClassWorker,
	"multiencode":                          ClassWorker,
	"mux":                                  ClassWorker,
	"partial-import":                       ClassWorker,
	"prepare-av":                           ClassWorker,
	"process-smil":                         ClassWorker,
	"publish-youtube":                      ClassWorker,
	"segment-video":                        ClassWorker,
	"segmentpreviews":                      ClassWorker,
	"select-tracks":                        ClassWorker,
	"silence":                              ClassWorker,
	"speechtotext":                         ClassWorker,
	"start-watson-transcription":           ClassWorker,
	"timelinepreviews":                     ClassWorker,
	"videogrid":                            ClassWorker,
	"waveform":                             ClassWorker,
	"zip":                                  ClassWorker,
}
