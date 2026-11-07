if (GIT_TAG AND (GIT_DESC OR GIT_COMMIT))
	message(FATAL_ERROR "cannot use GIT_DESC or GIT_COMMIT when using GIT_TAG")
endif()

if (NOT (GIT_TAG OR GIT_DESC OR GIT_COMMIT))
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
	execute_process(
		COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
		OUTPUT_VARIABLE GIT_COMMIT
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_QUIET
	)
	if (NOT GIT_COMMIT)
		set(GIT_COMMIT "${GIT_TAG}")
	endif()
	set(GIT_TAG true)

	message(STATUS "Building for git tag ${GIT_DESC}")
else()
	if (NOT GIT_DESC)
		execute_process(
			COMMAND ${GIT_EXECUTABLE} describe --tags --always --exclude apk-*
			OUTPUT_VARIABLE GIT_DESC
			OUTPUT_STRIP_TRAILING_WHITESPACE
		)
		message(STATUS "Setting version to ${GIT_DESC} from git")
	else()
		message(STATUS "Setting version to ${GIT_DESC} from parameters")
	endif()

	if (NOT GIT_COMMIT)
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
