package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

const (
	// markFlags = unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT
	markFlags = unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM
	// markMask  = unix.FAN_ACCESS | unix.FAN_OPEN
	// markMask = unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_DELETE
	markMask = unix.FAN_DELETE | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_CREATE | unix.FAN_MARK_REMOVE | unix.FAN_MOVE
)

type fanotifyEventInfoHeader struct {
	InfoType uint8
	Pad      uint8
	Len      uint16
}

type fanotifyEventInfoFid struct {
	fanotifyEventInfoHeader
	FSID uint64
}

func maskToHuman(mask uint64) string { //nolint:cyclop
	var flags []string
	if mask&unix.IN_CLOSE_WRITE > 0 {
		flags = append(flags, "FAN_CLOSE_WRITE")
	}
	if mask&unix.IN_ACCESS > 0 {
		flags = append(flags, "FAN_ACCESS")
	}
	if mask&unix.IN_ATTRIB > 0 {
		flags = append(flags, "FAN_ATTRIB")
	}
	if mask&unix.IN_CLOSE_NOWRITE > 0 {
		flags = append(flags, "FAN_CLOSE_NOWRITE")
	}
	if mask&unix.IN_CREATE > 0 {
		flags = append(flags, "FAN_CREATE")
	}
	if mask&unix.IN_DELETE > 0 {
		flags = append(flags, "FAN_DELETE")
	}
	if mask&unix.IN_DELETE_SELF > 0 {
		flags = append(flags, "FAN_DELETE_SELF")
	}
	if mask&unix.IN_IGNORED > 0 {
		flags = append(flags, "FAN_IGNORED")
	}
	if mask&unix.IN_ISDIR > 0 {
		flags = append(flags, "FAN_ISDIR")
	}
	if mask&unix.IN_MODIFY > 0 {
		flags = append(flags, "FAN_MODIFY")
	}
	if mask&unix.IN_MOVE_SELF > 0 {
		flags = append(flags, "fanMoveSelf")
	}
	if mask&unix.IN_MOVED_FROM > 0 {
		flags = append(flags, "fanMovedFrom")
	}
	if mask&unix.IN_MOVED_TO > 0 {
		flags = append(flags, "fanMovedTo")
	}
	if mask&unix.IN_OPEN > 0 {
		flags = append(flags, "FAN_OPEN")
	}
	if mask&unix.IN_Q_OVERFLOW > 0 {
		flags = append(flags, "FAN_Q_OVERFLOW")
	}
	if mask&unix.IN_UNMOUNT > 0 {
		flags = append(flags, "FAN_UNMOUNT")
	}

	return strings.Join(flags, ", ")
}

func readEvents(fd int, target string) {
	buf := make([]byte, 4096)

	mount_fd, err := unix.Open(target, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		log.Error().Err(err).Msg("unable to get mount fd")

		return
	}

	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			log.Error().Err(err).Msg("unable to read")

			return
		}

		rd := bytes.NewReader(buf)
		var offset int64

		for offset < int64(n) {
			var event unix.FanotifyEventMetadata

			err = binary.Read(rd, binary.LittleEndian, &event)
			if err != nil {
				log.Error().Caller().Err(err).Msgf("failed to read event metadata")
				break
			}

			// Read event info fid
			var fid fanotifyEventInfoFid

			err = binary.Read(rd, binary.LittleEndian, &fid)
			if err != nil {
				log.Error().Caller().Err(err).Msg("failed to read event fid")
				offset, _ = rd.Seek(offset+int64(event.Event_len), io.SeekStart)

				continue
			}

			// Although unix.FileHandle exists, it cannot be used with binary.Read() as the
			// variables inside are not exported.
			type fileHandleInfo struct {
				Bytes uint32
				Type  int32
			}

			// Read file handle information
			var fhInfo fileHandleInfo

			err = binary.Read(rd, binary.LittleEndian, &fhInfo)
			if err != nil {
				log.Error().Caller().Err(err).Msg("failed to read file handle info")
				offset, _ = rd.Seek(offset+int64(event.Event_len), io.SeekStart)

				continue
			}

			// Read file handle
			fileHandle := make([]byte, fhInfo.Bytes)

			err = binary.Read(rd, binary.LittleEndian, &fileHandle)
			if err != nil {
				log.Error().Caller().Err(err).Msg("failed to read file handle")
				offset, _ = rd.Seek(offset+int64(event.Event_len), io.SeekStart)

				continue
			}

			fh := unix.NewFileHandle(fhInfo.Type, fileHandle)

			fd, err := unix.OpenByHandleAt(mount_fd, fh, os.O_RDONLY)
			if err != nil {
				if !errors.Is(err, unix.ESTALE) {
					// This is a common error when removing a folder containing multiple files at once.
					// It can be safely ignored, because the more important underlying folder event does not produce such an error
					log.Error().Caller().Err(err).Msg("failed to open file handle")
				}
				offset, _ = rd.Seek(offset+int64(event.Event_len), io.SeekStart)

				continue
			}

			// Determine the directory of the created or deleted file.
			dir, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
			if err != nil {
				log.Error().Caller().Err(err).Msg("failed to read symlink")
				offset, _ = rd.Seek(offset+int64(event.Event_len), io.SeekStart)

				continue
			}

			// Close fd to not run into "too many open files" error
			_ = unix.Close(fd)

			// If the target file has been deleted, the returned value might contain a " (deleted)" suffix.
			// This needs to be removed.
			dir = strings.TrimSuffix(dir, " (deleted)")

			// Get start and end index of filename string
			start, _ := rd.Seek(0, io.SeekCurrent)
			end := offset + int64(event.Event_len)

			// Read filename from buf and remove NULL terminator
			filename := unix.ByteSliceToString(buf[start:end])
			eventPath := filepath.Join(dir, filename)

			log.Info().Msgf("%s, %s", eventPath, maskToHuman(event.Mask))

			// Set the offset to the start of the next event
			offset, err = rd.Seek(end, io.SeekStart)
			if err != nil {
				log.Error().Err(err).Msgf("failed to set new offset")

				break
			}
		}
	}
}

func main() {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY) //nolint:nosnakecase,varnamelen
	if err != nil {
		log.Error().Err(err).Msg("init failed")

		return
	}

	target := "/tmp"

	err = unix.FanotifyMark(fd, markFlags, markMask, unix.AT_FDCWD, target) //nolint:nosnakecase
	if err != nil {
		log.Error().Err(err).Msg("mark failed")

		return
	}

	for {
		readEvents(fd, target)
	}
}
