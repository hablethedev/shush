package main

import (
    "crypto/rand"
    "database/sql"
    "encoding/base64"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "strings"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/time/rate"
    "gopkg.in/yaml.v2"
)

type Config struct {
    KeyLength       int    `yaml:"key_length"`
    RequestPerMin   int    `yaml:"request_per_min"`
    SqliteFilename  string `yaml:"sqlite_filename"`
    HTTPPort        string `yaml:"http_port"`
    HTTPSPort       string `yaml:"https_port"`
    CertFile        string `yaml:"cert_file"`
    KeyFile         string `yaml:"key_file"`
    ForceHTTPS      bool   `yaml:"force_https"`
    DefaultScheme   string `yaml:"default_scheme"`
    DBTableName     string `yaml:"db_table_name"`
    ReadTimeoutSec  int    `yaml:"read_timeout_sec"`
    WriteTimeoutSec int    `yaml:"write_timeout_sec"`
    IdleTimeoutSec  int    `yaml:"idle_timeout_sec"`
    HomepageBanner  string `yaml:"homepage_banner"`
}

var (
    cfg     Config
    limiter = make(map[string]*rate.Limiter)
)

func loadConfig(path string) Config {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        log.Printf("Config not found, creating default at %s", path)
        def := defaultConfig()
        out, _ := yaml.Marshal(def)
        if writeErr := ioutil.WriteFile(path, out, 0644); writeErr != nil {
            log.Printf("Failed to write default config: %v", writeErr)
        }
        return def
    }
    var c Config
    if err := yaml.Unmarshal(data, &c); err != nil {
        log.Printf("Invalid config format, using defaults: %v", err)
        return defaultConfig()
    }
    return applyDefaults(c)
}

func defaultConfig() Config {
    return Config{
        KeyLength:       8,
        RequestPerMin:   60,
        SqliteFilename:  "urls.db",
        HTTPPort:        ":8080",
        HTTPSPort:       ":8443",
        CertFile:        "server.crt",
        KeyFile:         "server.key",
        ForceHTTPS:      false,
        DefaultScheme:   "https://",
        DBTableName:     "urls",
        ReadTimeoutSec:  5,
        WriteTimeoutSec: 10,
        IdleTimeoutSec:  120,
        HomepageBanner:  "shush v0.1 (silence) — URL shortener server",
    }
}

func applyDefaults(c Config) Config {
    d := defaultConfig()
    if c.KeyLength == 0 {
        c.KeyLength = d.KeyLength
    }
    if c.RequestPerMin == 0 {
        c.RequestPerMin = d.RequestPerMin
    }
    if c.SqliteFilename == "" {
        c.SqliteFilename = d.SqliteFilename
    }
    if c.HTTPPort == "" {
        c.HTTPPort = d.HTTPPort
    }
    if c.HTTPSPort == "" {
        c.HTTPSPort = d.HTTPSPort
    }
    if c.CertFile == "" {
        c.CertFile = d.CertFile
    }
    if c.KeyFile == "" {
        c.KeyFile = d.KeyFile
    }
    if c.DefaultScheme == "" {
        c.DefaultScheme = d.DefaultScheme
    }
    if c.DBTableName == "" {
        c.DBTableName = d.DBTableName
    }
    if c.ReadTimeoutSec == 0 {
        c.ReadTimeoutSec = d.ReadTimeoutSec
    }
    if c.WriteTimeoutSec == 0 {
        c.WriteTimeoutSec = d.WriteTimeoutSec
    }
    if c.IdleTimeoutSec == 0 {
        c.IdleTimeoutSec = d.IdleTimeoutSec
    }
    if c.HomepageBanner == "" {
        c.HomepageBanner = d.HomepageBanner
    }
    return c
}

func getRateLimiter(ip string) *rate.Limiter {
    if rl, ok := limiter[ip]; ok {
        return rl
    }
    rl := rate.NewLimiter(rate.Every(time.Minute/time.Duration(cfg.RequestPerMin)), cfg.RequestPerMin)
    limiter[ip] = rl
    return rl
}

func generateKey(n int) (string, error) {
    b := make([]byte, n)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "= "), nil
}

func sanitizeURL(u string) string {
    u = strings.TrimSpace(u)
    u = strings.ReplaceAll(u, "\n", "")
    u = strings.ReplaceAll(u, "\r", "")
    if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
        scheme := "https://"
        if !cfg.ForceHTTPS {
            scheme = "http://"
        }
        u = scheme + u
    }
    return u
}

func main() {
    cfgPath := flag.String("config", "config.yaml", "Path to config file")
    flag.Parse()

    cfg = loadConfig(*cfgPath)
    log.Printf("Loaded config: %+v", cfg)

    db, err := sql.Open("sqlite3", cfg.SqliteFilename)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    createStmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
        key TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`, cfg.DBTableName)
    if _, err := db.Exec(createStmt); err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/short", shortenHandler(db))
    mux.HandleFunc("/l/", redirectHandler(db))
    mux.HandleFunc("/", homeHandler)

    if cfg.ForceHTTPS {
        go func() {
            http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                target := "https://" + r.Host + r.URL.RequestURI()
                http.Redirect(w, r, target, http.StatusMovedPermanently)
            })
            log.Printf("Redirecting HTTP %s to HTTPS %s", cfg.HTTPPort, cfg.HTTPSPort)
            log.Fatal(http.ListenAndServe(cfg.HTTPPort, nil))
        }()

        srv := &http.Server{
            Addr:         cfg.HTTPSPort,
            Handler:      rateMiddleware(mux),
            ReadTimeout:  time.Duration(cfg.ReadTimeoutSec) * time.Second,
            WriteTimeout: time.Duration(cfg.WriteTimeoutSec) * time.Second,
            IdleTimeout:  time.Duration(cfg.IdleTimeoutSec) * time.Second,
        }
        log.Printf("Starting HTTPS server on %s", cfg.HTTPSPort)
        log.Fatal(srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
    } else {
        srv := &http.Server{
            Addr:         cfg.HTTPPort,
            Handler:      rateMiddleware(mux),
            ReadTimeout:  time.Duration(cfg.ReadTimeoutSec) * time.Second,
            WriteTimeout: time.Duration(cfg.WriteTimeoutSec) * time.Second,
            IdleTimeout:  time.Duration(cfg.IdleTimeoutSec) * time.Second,
        }
        log.Printf("Starting HTTP server on %s", cfg.HTTPPort)
        log.Fatal(srv.ListenAndServe())
    }
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, cfg.HomepageBanner)
    fmt.Fprintln(w, "")
    fmt.Fprintln(w, "POST /short?url=<url>")
    fmt.Fprintln(w, "GET /l/<key> to redirect")
}

func shortenHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        orig := r.URL.Query().Get("url")
        if orig == "" {
            http.Error(w, "Missing URL parameter", http.StatusBadRequest)
            return
        }
        originalURL := sanitizeURL(orig)

        var existingKey string
        queryExisting := fmt.Sprintf("SELECT key FROM %s WHERE url = ?", cfg.DBTableName)
        err := db.QueryRow(queryExisting, originalURL).Scan(&existingKey)
        if err == nil {
            scheme := "https"
            if !cfg.ForceHTTPS {
                scheme = "http"
            }
            fmt.Fprintf(w, "%s://%s/l/%s", scheme, r.Host, existingKey)
            return
        } else if err != sql.ErrNoRows {
            http.Error(w, "db error", http.StatusInternalServerError)
            return
        }

        var key string
        for {
            k, err := generateKey(cfg.KeyLength)
            if err != nil {
                http.Error(w, "Key gen error", http.StatusInternalServerError)
                return
            }
            key = k
            var exists string
            query := fmt.Sprintf("SELECT key FROM %s WHERE key = ?", cfg.DBTableName)
            err = db.QueryRow(query, key).Scan(&exists)
            if err == sql.ErrNoRows {
                break
            } else if err != nil {
                http.Error(w, "db error", http.StatusInternalServerError)
                return
            }
        }

        insert := fmt.Sprintf("INSERT INTO %s(key, url) VALUES(?, ?)", cfg.DBTableName)
        if _, err := db.Exec(insert, key, originalURL); err != nil {
            http.Error(w, "db insert error", http.StatusInternalServerError)
            return
        }

        scheme := "https"
        if !cfg.ForceHTTPS {
            scheme = "http"
        }
        fmt.Fprintf(w, "%s://%s/l/%s", scheme, r.Host, key)
    }
}


func redirectHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        key := strings.TrimPrefix(r.URL.Path, "/l/")
        var originalURL string
        query := fmt.Sprintf("SELECT url FROM %s WHERE key = ?", cfg.DBTableName)
        err := db.QueryRow(query, key).Scan(&originalURL)
        if err == sql.ErrNoRows {
            http.NotFound(w, r)
            return
        } else if err != nil {
            http.Error(w, "db error", http.StatusInternalServerError)
            return
        }
        http.Redirect(w, r, originalURL, http.StatusFound)
    }
}

func rateMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := strings.Split(r.RemoteAddr, ":")[0]
        rl := getRateLimiter(ip)
        if !rl.Allow() {
            http.Error(w, "Rate limit exceeded!", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}
