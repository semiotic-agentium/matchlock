package image

import (
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jingkaihe/matchlock/internal/errx"
)

const (
	imageScopeLocal    = "local"
	imageScopeRegistry = "registry"
)

type OCIConfig struct {
	User       string            `json:"user,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	Entrypoint []string          `json:"entrypoint,omitempty"`
	Cmd        []string          `json:"cmd,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
}

type ImageMeta struct {
	Tag       string     `json:"tag"`
	Digest    string     `json:"digest,omitempty"`
	Size      int64      `json:"size"`
	CreatedAt time.Time  `json:"created_at"`
	Source    string     `json:"source,omitempty"`
	OCI       *OCIConfig `json:"oci,omitempty"`
}

type ImageInfo struct {
	Tag        string
	RootfsPath string
	Meta       ImageMeta
}

type Store struct {
	baseDir string
	db      *sql.DB
	initErr error
}

func NewStore(baseDir string) *Store {
	if baseDir == "" {
		baseDir = filepath.Join(defaultImageCacheDir(), "local")
	}
	_ = os.MkdirAll(baseDir, 0755)
	db, err := openImageDBForLocalBase(baseDir)
	return &Store{
		baseDir: baseDir,
		db:      db,
		initErr: err,
	}
}

func (s *Store) ready() error {
	if s.initErr != nil {
		return errx.Wrap(ErrStoreRead, s.initErr)
	}
	if s.db == nil {
		return ErrStoreRead
	}
	return nil
}

func (s *Store) Save(tag string, rootfsPath string, meta ImageMeta) error {
	if err := s.ready(); err != nil {
		return err
	}

	dir := filepath.Join(s.baseDir, sanitizeRef(tag))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errx.Wrap(ErrCreateDir, err)
	}

	destPath := filepath.Join(dir, "rootfs.ext4")

	src, err := os.Open(rootfsPath)
	if err != nil {
		return errx.With(ErrStoreSave, ": open source rootfs: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return errx.With(ErrStoreSave, ": create dest rootfs: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(destPath)
		return errx.With(ErrStoreSave, ": copy rootfs: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(destPath)
		return errx.With(ErrStoreSave, ": flush rootfs: %w", err)
	}

	meta.Tag = tag
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	fi, err := os.Stat(destPath)
	if err == nil {
		meta.Size = fi.Size()
	}
	if err := upsertImageMeta(s.db, imageScopeLocal, tag, meta, destPath); err != nil {
		return err
	}
	return nil
}

func (s *Store) Get(tag string) (*BuildResult, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	info, err := getImageMeta(s.db, imageScopeLocal, tag)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(info.RootfsPath); err != nil {
		return nil, errx.With(ErrImageNotFound, ": rootfs for %q", tag)
	}
	fi, _ := os.Stat(info.RootfsPath)
	return &BuildResult{
		RootfsPath: info.RootfsPath,
		Digest:     info.Meta.Digest,
		Size:       fi.Size(),
		Cached:     true,
		OCI:        info.Meta.OCI,
	}, nil
}

func (s *Store) List() ([]ImageInfo, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return listImageMeta(s.db, imageScopeLocal)
}

func (s *Store) Remove(tag string) error {
	if err := s.ready(); err != nil {
		return err
	}
	dir := filepath.Join(s.baseDir, sanitizeRef(tag))
	res, err := s.db.Exec(`DELETE FROM images WHERE scope = ? AND tag = ?`, imageScopeLocal, tag)
	if err != nil {
		return errx.With(ErrStoreSave, ": remove local metadata: %w", err)
	}
	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		if _, statErr := os.Stat(dir); statErr != nil {
			return errx.With(ErrImageNotFound, ": %q", tag)
		}
	}
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return errx.With(ErrStoreSave, ": remove local rootfs dir: %w", err)
	}
	return nil
}

// SaveRegistryCache records metadata for a registry-cached image.
func SaveRegistryCache(tag string, cacheDir string, rootfsPath string, meta ImageMeta) error {
	if cacheDir == "" {
		cacheDir = defaultImageCacheDir()
	}
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return errx.Wrap(ErrCreateDir, err)
	}
	db, err := openImageDBForCacheDir(cacheDir)
	if err != nil {
		return errx.With(ErrStoreSave, ": open registry metadata DB: %w", err)
	}
	defer db.Close()

	meta.Tag = tag
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	if fi, err := os.Stat(rootfsPath); err == nil {
		meta.Size = fi.Size()
	}
	return upsertImageMeta(db, imageScopeRegistry, tag, meta, rootfsPath)
}

// GetRegistryCache returns a registry-cached image metadata entry as a BuildResult.
func GetRegistryCache(tag string, cacheDir string) (*BuildResult, error) {
	if cacheDir == "" {
		cacheDir = defaultImageCacheDir()
	}
	db, err := openImageDBForCacheDir(cacheDir)
	if err != nil {
		return nil, errx.With(ErrStoreRead, ": open registry metadata DB: %w", err)
	}
	defer db.Close()

	info, err := getImageMeta(db, imageScopeRegistry, tag)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(info.RootfsPath)
	if err != nil {
		return nil, errx.With(ErrImageNotFound, ": rootfs for %q", tag)
	}
	return &BuildResult{
		RootfsPath: info.RootfsPath,
		Digest:     info.Meta.Digest,
		Size:       fi.Size(),
		Cached:     true,
		OCI:        info.Meta.OCI,
	}, nil
}

// RemoveRegistryCache removes a registry-cached image by tag.
func RemoveRegistryCache(tag string, cacheDir string) error {
	if cacheDir == "" {
		cacheDir = defaultImageCacheDir()
	}

	dir := filepath.Join(cacheDir, sanitizeRef(tag))
	if dir == filepath.Clean(cacheDir) || dir == filepath.Join(cacheDir, "local") {
		return errx.With(ErrImageNotFound, ": %q", tag)
	}

	db, err := openImageDBForCacheDir(cacheDir)
	if err != nil {
		return errx.With(ErrStoreSave, ": open registry metadata DB: %w", err)
	}
	defer db.Close()

	res, err := db.Exec(`DELETE FROM images WHERE scope = ? AND tag = ?`, imageScopeRegistry, tag)
	if err != nil {
		return errx.With(ErrStoreSave, ": remove registry metadata: %w", err)
	}
	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		if _, statErr := os.Stat(dir); statErr != nil {
			return errx.With(ErrImageNotFound, ": %q", tag)
		}
	}

	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return errx.With(ErrStoreSave, ": remove registry cache dir: %w", err)
	}
	return nil
}

// ListRegistryCache lists images cached from registry pulls (non-local store).
func ListRegistryCache(cacheDir string) ([]ImageInfo, error) {
	if cacheDir == "" {
		cacheDir = defaultImageCacheDir()
	}
	db, err := openImageDBForCacheDir(cacheDir)
	if err != nil {
		return nil, errx.With(ErrStoreRead, ": open registry metadata DB: %w", err)
	}
	defer db.Close()

	return listImageMeta(db, imageScopeRegistry)
}

func upsertImageMeta(db *sql.DB, scope, tag string, meta ImageMeta, rootfsPath string) error {
	var ociJSON []byte
	if meta.OCI != nil {
		data, err := json.Marshal(meta.OCI)
		if err != nil {
			return errx.With(ErrMetadata, ": marshal OCI config: %w", err)
		}
		ociJSON = data
	}
	createdAt := meta.CreatedAt.UTC().Format(time.RFC3339Nano)
	updatedAt := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(
		`INSERT INTO images(scope, tag, digest, size, created_at, source, rootfs_path, oci_json, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scope, tag) DO UPDATE SET
		   digest = excluded.digest,
		   size = excluded.size,
		   created_at = excluded.created_at,
		   source = excluded.source,
		   rootfs_path = excluded.rootfs_path,
		   oci_json = excluded.oci_json,
		   updated_at = excluded.updated_at`,
		scope,
		tag,
		meta.Digest,
		meta.Size,
		createdAt,
		meta.Source,
		rootfsPath,
		ociJSON,
		updatedAt,
	)
	if err != nil {
		return errx.With(ErrStoreSave, ": upsert image metadata: %w", err)
	}
	return nil
}

func getImageMeta(db *sql.DB, scope, tag string) (*ImageInfo, error) {
	row := db.QueryRow(
		`SELECT tag, digest, size, created_at, source, rootfs_path, oci_json
		   FROM images
		  WHERE scope = ? AND tag = ?`,
		scope,
		tag,
	)

	var (
		info      ImageInfo
		createdAt string
		ociJSON   []byte
	)
	if err := row.Scan(&info.Tag, &info.Meta.Digest, &info.Meta.Size, &createdAt, &info.Meta.Source, &info.RootfsPath, &ociJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, errx.With(ErrImageNotFound, ": %q", tag)
		}
		return nil, errx.With(ErrStoreRead, ": get image metadata: %w", err)
	}
	if createdAt != "" {
		t, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			t, err = time.Parse(time.RFC3339, createdAt)
			if err != nil {
				return nil, errx.With(ErrStoreRead, ": parse created_at: %w", err)
			}
		}
		info.Meta.CreatedAt = t
	}
	info.Meta.Tag = info.Tag
	if len(ociJSON) > 0 {
		var oci OCIConfig
		if err := json.Unmarshal(ociJSON, &oci); err != nil {
			return nil, errx.With(ErrStoreRead, ": decode OCI config: %w", err)
		}
		info.Meta.OCI = &oci
	}
	return &info, nil
}

func listImageMeta(db *sql.DB, scope string) ([]ImageInfo, error) {
	rows, err := db.Query(
		`SELECT tag, digest, size, created_at, source, rootfs_path, oci_json
		   FROM images
		  WHERE scope = ?
		  ORDER BY created_at DESC`,
		scope,
	)
	if err != nil {
		return nil, errx.With(ErrStoreRead, ": list image metadata: %w", err)
	}
	defer rows.Close()

	var images []ImageInfo
	for rows.Next() {
		var (
			info      ImageInfo
			createdAt string
			ociJSON   []byte
		)
		if err := rows.Scan(&info.Tag, &info.Meta.Digest, &info.Meta.Size, &createdAt, &info.Meta.Source, &info.RootfsPath, &ociJSON); err != nil {
			return nil, errx.With(ErrStoreRead, ": scan image metadata: %w", err)
		}
		if createdAt != "" {
			t, err := time.Parse(time.RFC3339Nano, createdAt)
			if err != nil {
				t, err = time.Parse(time.RFC3339, createdAt)
				if err != nil {
					return nil, errx.With(ErrStoreRead, ": parse created_at: %w", err)
				}
			}
			info.Meta.CreatedAt = t
		}
		info.Meta.Tag = info.Tag
		if len(ociJSON) > 0 {
			var oci OCIConfig
			if err := json.Unmarshal(ociJSON, &oci); err != nil {
				return nil, errx.With(ErrStoreRead, ": decode OCI config: %w", err)
			}
			info.Meta.OCI = &oci
		}
		images = append(images, info)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.With(ErrStoreRead, ": iterate image metadata: %w", err)
	}
	return images, nil
}
