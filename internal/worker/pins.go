package worker

// The pinned transcription toolchain. These are the recorded sha256 digests
// of the tools the reference VTT outputs were produced by. The worker
// ASSERTS these at startup and refuses to run on drift: a byte-diff against
// the reference outputs is only meaningful for exactly this toolchain
// (ADR-009's determinism-is-per-invocation lesson, measured for whisper on
// 2026-08-13).
const (
	pinWhisperCLI = "82433e05609db8f1951345835122c284e09362c7a5423af9fd8f921de6d2f246"
	pinModel      = "60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe"
	pinFFmpeg     = "df401a840625f4fe1e0eacf72663d9d1e200d7bf1f5f942a4804d1471e877f5c"
	// ffprobe joined the pin set for increment 2's inspect op (same static
	// build as ffmpeg, pinned alongside it). Verified by the
	// inspect op at use, NOT by VerifyToolchain — increment-1 tool dirs
	// carry only the base three and must keep verifying.
	pinFFprobe = "30128a8b03723c7693bc9d04d9bc7470a1cdd9f3d2725e10ed0a6baacf574672"
)
