if (GIT_TAG AND (GIT_DESC OR GIT_COMMIT))
	message(FATAL_ERROR "cannot use GIT_DESC or GIT_COMMIT when using GIT_TAG")
endif()

# An exported GIT_DIR/GIT_WORK_TREE (e.g. when run from a git hook) would point git at another
# repository and defeat the check below.
unset(ENV{GIT_DIR})
unset(ENV{GIT_WORK_TREE})

# Only trust .git at the top of the source tree, not an unrelated enclosing repository (e.g. a
# packaging repo around a release tarball): then the version must be passed in, as without .git.
execute_process(
	COMMAND ${GIT_EXECUTABLE} rev-parse --show-toplevel
	OUTPUT_VARIABLE GIT_TOPLEVEL
	OUTPUT_STRIP_TRAILING_WHITESPACE
	ERROR_QUIET
)
file(REAL_PATH "." SOURCE_DIR_REAL)
if (GIT_TOPLEVEL)
	file(REAL_PATH "${GIT_TOPLEVEL}" GIT_TOPLEVEL)
endif()
if (GIT_TOPLEVEL STREQUAL SOURCE_DIR_REAL)
	set(OWN_GIT_REPO true)
else()
	set(OWN_GIT_REPO false)
endif()

if (OWN_GIT_REPO AND NOT (GIT_TAG OR GIT_DESC OR GIT_COMMIT))
	execute_process(
		# apk-<sha> tags mark the xerktech fork's APK releases (APK-Release.yml),
		# not versions: matching one would make git_commit "apk-<sha>" (breaking
		# the dashboard's APK lookup) or the version "apk-<sha>".
		COMMAND ${GIT_EXECUTABLE} describe --exact-match --tags --exclude apk-*
		OUTPUT_VARIABLE GIT_TAG
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_QUIET
	)
endif()

if (GIT_TAG)
	set(GIT_DESC "${GIT_TAG}")
	# xerktech fork: the dashboard fetches the APK by commit (release apk-<sha>), even for a
	# tagged build, so use the commit when .git can tell it, the tag name otherwise.
	if (OWN_GIT_REPO)
		execute_process(
			COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
			OUTPUT_VARIABLE GIT_COMMIT
			OUTPUT_STRIP_TRAILING_WHITESPACE
			ERROR_QUIET
		)
	endif()
	if (NOT GIT_COMMIT)
		set(GIT_COMMIT "${GIT_TAG}")
	endif()
	set(GIT_TAG true)

	message(STATUS "Building for git tag ${GIT_DESC}")
else()
	if (OWN_GIT_REPO AND NOT GIT_DESC)
		execute_process(
			COMMAND ${GIT_EXECUTABLE} describe --tags --always --exclude apk-*
			OUTPUT_VARIABLE GIT_DESC
			OUTPUT_STRIP_TRAILING_WHITESPACE
		)
		message(STATUS "Setting version to ${GIT_DESC} from git")
	elseif (GIT_DESC)
		message(STATUS "Setting version to ${GIT_DESC} from parameters")
	endif()

	if (OWN_GIT_REPO AND NOT GIT_COMMIT)
		execute_process(
			COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
			OUTPUT_VARIABLE GIT_COMMIT
		)
		string(STRIP "${GIT_COMMIT}" GIT_COMMIT)
	endif()

	if (NOT GIT_DESC)
		message(FATAL_ERROR "GIT_DESC cannot be inferred from .git and was not provided at build time")
	endif()

	if (GIT_COMMIT)
		message(STATUS "Setting commit to ${GIT_COMMIT}")
	else()
		message(FATAL_ERROR "GIT_COMMIT cannot be inferred from .git and was not provided at build time")
	endif()
	set(GIT_TAG false)
endif()

configure_file(${INPUT_FILE} ${OUTPUT_FILE})
configure_file(${INPUT_FILE_1} ${OUTPUT_FILE_1})
