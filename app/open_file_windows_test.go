//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// openFileTempDir returns a test directory without 8.3 components. CI temp paths
// can contain them, and validateSharedFile refuses such a share.
func openFileTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	name, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 32768)
	n, _, callErr := kernel32.NewProc("GetLongPathNameW").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		t.Fatalf("GetLongPathNameW: %v", callErr)
	}
	return syscall.UTF16ToString(buf[:n])
}

func writeOpenFileFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("shared file test"), 0600); err != nil {
		t.Fatal(err)
	}
}

func makeOpenFileJunction(t *testing.T, link, target string) {
	t.Helper()
	cmd := exec.Command(system32("cmd.exe"), "/d", "/c", "mklink", "/J", link, target)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(link); err != nil {
			t.Errorf("remove junction: %v", err)
		}
	})
}

func TestValidateSharedFile(t *testing.T) {
	share := openFileTempDir(t)
	writeOpenFileFixture(t, filepath.Join(share, "folder", "Report.txt"))
	for _, rel := range []string{"folder/Report.txt", "folder/report.TXT"} {
		got, err := validateSharedFile(share, rel)
		if err != nil || !openFileOrdinalEqual(got, filepath.Join(share, "folder", "Report.txt")) {
			t.Fatalf("%q: %q, %v", rel, got, err)
		}
		if strings.HasPrefix(got, `\\?\`) {
			t.Fatal("extended prefix passed to opener")
		}
	}
	for _, rel := range []string{"folder", "folder/missing.txt", "../outside.txt", "folder/Report.txt:stream"} {
		if got, err := validateSharedFile(share, rel); err == nil {
			t.Errorf("accepted %q: %q", rel, got)
		}
	}
	for _, root := range []string{"", ".", `\\server\share`, `\\?\C:\share`, share + `\..`, share + `\`} {
		if _, err := validateSharedFile(root, "folder/Report.txt"); err == nil {
			t.Errorf("accepted share %q", root)
		}
	}
	if _, ok := parseOpenFileRequest(openFileTestLine("folder/Report.txt:stream")); ok {
		t.Fatal("ADS survived request parsing")
	}
}

func TestValidateSharedFileRejectsSymlinks(t *testing.T) {
	share := openFileTempDir(t)
	writeOpenFileFixture(t, filepath.Join(share, "real", "file.txt"))
	link := filepath.Join(share, "link.txt")
	if err := os.Symlink(filepath.Join(share, "real", "file.txt"), link); err != nil {
		if errors.Is(err, syscall.Errno(1314)) || errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			t.Skip("symlink privilege unavailable")
		}
		t.Fatal(err)
	}
	if _, err := validateSharedFile(share, "link.txt"); err == nil {
		t.Fatal("accepted file symlink")
	}
	dirLink := filepath.Join(share, "link-dir")
	if err := os.Symlink(filepath.Join(share, "real"), dirLink); err != nil {
		t.Fatal(err)
	}
	if _, err := validateSharedFile(share, "link-dir/file.txt"); err == nil {
		t.Fatal("accepted intermediate symlink")
	}
	if _, err := validateSharedFile(dirLink, "file.txt"); err == nil {
		t.Fatal("accepted symlink share root")
	}
}

func TestValidateSharedFileRejectsJunctions(t *testing.T) {
	base := openFileTempDir(t)
	share := filepath.Join(base, "share")
	target := filepath.Join(base, "target")
	writeOpenFileFixture(t, filepath.Join(share, "file.txt"))
	writeOpenFileFixture(t, filepath.Join(target, "nested", "file.txt"))
	middle := filepath.Join(share, "junction")
	makeOpenFileJunction(t, middle, target)
	if _, err := validateSharedFile(share, "file.txt"); err != nil {
		t.Fatalf("ordinary file in share with junction: %v", err)
	}
	if _, err := validateSharedFile(share, "junction/nested/file.txt"); err == nil {
		t.Fatal("accepted junction in requested path")
	}
	if _, err := validateSharedFile(middle, "nested/file.txt"); err == nil {
		t.Fatal("accepted junction share root")
	}
	if _, err := validateSharedFile(filepath.Join(middle, "nested"), "file.txt"); err == nil {
		t.Fatal("accepted junction above share root")
	}
}

func TestValidateSharedFileRejectsHardLinks(t *testing.T) {
	base := openFileTempDir(t)
	share := filepath.Join(base, "share")
	original := filepath.Join(share, "file.txt")
	writeOpenFileFixture(t, original)
	if err := os.Link(original, filepath.Join(base, "outside.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := validateSharedFile(share, "file.txt"); err == nil {
		t.Fatal("accepted multiply linked file")
	}
}

func TestValidateSharedFileRejectsShortNames(t *testing.T) {
	share := openFileTempDir(t)
	longName := filepath.Join(share, "Long directory name", "Long document name.txt")
	writeOpenFileFixture(t, longName)
	proc := kernel32.NewProc("GetShortPathNameW")
	name, err := syscall.UTF16PtrFromString(longName)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 32768)
	n, _, callErr := proc.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		t.Fatalf("GetShortPathNameW: %v", callErr)
	}
	short := syscall.UTF16ToString(buf[:n])
	shortFile, shortDir := filepath.Base(short), filepath.Base(filepath.Dir(short))
	fileAlias := !openFileOrdinalEqual(shortFile, filepath.Base(longName))
	dirAlias := !openFileOrdinalEqual(shortDir, filepath.Base(filepath.Dir(longName)))
	if !fileAlias && !dirAlias {
		t.Skip("8.3 short names are disabled")
	}
	if fileAlias {
		if _, err := validateSharedFile(share, "Long directory name/"+shortFile); err == nil {
			t.Fatal("accepted file short name")
		}
	}
	if dirAlias {
		if _, err := validateSharedFile(filepath.Dir(short), "Long document name.txt"); err == nil {
			t.Fatal("accepted share with short name")
		}
		if _, err := validateSharedFile(share, shortDir+"/Long document name.txt"); err == nil {
			t.Fatal("accepted directory short name")
		}
	}
}

func TestOpenFileReparseTagPolicy(t *testing.T) {
	if !allowedOpenFileReparseTag(0, 0) {
		t.Fatal("rejected ordinary file")
	}
	for i := uint32(0); i < 16; i++ {
		if !allowedOpenFileReparseTag(fileAttributeReparsePoint, 0x9000001A|(i<<12)) {
			t.Errorf("rejected cloud tag %d", i)
		}
	}
	for _, tag := range []uint32{0, ioReparseTagSymlink, ioReparseTagMountPoint, 0x8000001B, 0x9001001A, 0xA000001A} {
		if allowedOpenFileReparseTag(fileAttributeReparsePoint, tag) {
			t.Errorf("accepted reparse tag %#x", tag)
		}
	}
}

func TestOpenFileFinalPathAndOrdinalComparison(t *testing.T) {
	if !openFileOrdinalEqual(`C:\share\보고서.TXT`, `c:\SHARE\보고서.txt`) {
		t.Fatal("ordinal case comparison failed")
	}
	for _, other := range []string{`C:\share-other\file.txt`, `C:\share\FILE~1.TXT`, `C:\elsewhere\file.txt`} {
		if openFileOrdinalEqual(`C:\share\file.txt`, other) {
			t.Errorf("accepted different path %s", other)
		}
	}
	for _, path := range []string{`\\?\UNC\server\share\file.txt`, `\\.\C:\file.txt`, `C:\file.txt`, `\\?\Volume{test}\file.txt`, `\\?\C:file.txt`} {
		if _, ok := localOpenFilePath(path); ok {
			t.Errorf("accepted non-DOS final path %s", path)
		}
	}
}

func TestFileOpenersRejectInterpreters(t *testing.T) {
	dir := t.TempDir()
	for _, name := range strings.Fields("python pythonw python3 python3.14 python-custom py pyw powershell pwsh cmd wscript cscript mshta rundll32 regsvr32 node java javaw bash wsl conhost") {
		path := filepath.Join(dir, strings.ToUpper(name)+".EXE")
		writeOpenFileFixture(t, path)
		if err := validateFileOpener(path); err == nil {
			t.Errorf("accepted interpreter %s", name)
		}
	}
	reader := filepath.Join(dir, "reader.exe")
	writeOpenFileFixture(t, reader)
	if err := validateFileOpener(reader); err != nil {
		t.Fatal(err)
	}
	if err := validateFileOpener(filepath.Join(dir, "missing.exe")); err == nil {
		t.Fatal("accepted missing executable")
	}
}

func TestOpenSharedFileRequiresCurrentSessionShare(t *testing.T) {
	previous := bootShare.Load()
	bootShare.Store(nil)
	t.Cleanup(func() { bootShare.Store(previous) })
	if err := openSharedWindowsFile(t.TempDir(), "file.txt"); err == nil {
		t.Fatal("opened without current session share")
	}
}

func TestOpenSharedFilePolicyRefusals(t *testing.T) {
	share := openFileTempDir(t)
	previous := bootShare.Load()
	bootShare.Store(&share)
	t.Cleanup(func() { bootShare.Store(previous) })
	// No target file exists and the fake executables cannot run. Assert the
	// policy error so filesystem refusal cannot mask a missing policy check.
	external := t.TempDir()
	interpreter := filepath.Join(external, "python3.exe")
	inside := filepath.Join(share, "reader.exe")
	writeOpenFileFixture(t, interpreter)
	writeOpenFileFixture(t, inside)
	id := strings.Repeat("a", 32)
	for _, tc := range []struct {
		name, ext, appID, appPath, want string
	}{
		{"type not allowed", ".pdf", "", "", "file type is not allowed"},
		{"revoked app", ".txt", id, "", "file opener is no longer approved"},
		{"interpreter", ".txt", id, interpreter, "interpreters cannot be file openers"},
		{"app in share", ".txt", id, inside, "file opener overlaps the running share"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			apps := approvedAppPreferences{SchemaVersion: 1}
			if tc.appPath != "" {
				apps.Apps = []approvedWindowsApp{{ID: id, Name: "Opener", Path: tc.appPath}}
			}
			if err := saveApprovedWindowsApps(dir, apps); err != nil {
				t.Fatal(err)
			}
			if err := saveApprovedFileTypes(dir, approvedFileTypePreferences{Types: []approvedFileType{{Ext: tc.ext, App: tc.appID}}}); err != nil {
				t.Fatal(err)
			}
			if err := openSharedWindowsFile(dir, "file.txt"); err == nil || err.Error() != tc.want {
				t.Fatalf("policy refusal = %v, want %q", err, tc.want)
			}
		})
	}
}
