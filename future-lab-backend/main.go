package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time" // ▼▼▼ time パッケージをインポート ▼▼▼

	"github.com/jackc/pgx/v4"
)

// --- Structs ---
type UserRequest struct {
	UserID      string `json:"userId"`
	PackageName string `json:"packageName,omitempty"`
}
type ExperimentResponse struct {
	Status             string         `json:"status"`
	Message            string         `json:"message"`
	ServicePorts       map[string]int `json:"servicePorts,omitempty"`
	PublicServicePorts map[string]int `json:"publicServicePorts,omitempty"`
}
type SQLRequest struct {
	UserID   string `json:"userId"`
	SQLQuery string `json:"sqlQuery"`
}
type SQLResponse struct {
	Status  string          `json:"status"`
	Message string          `json:"message,omitempty"`
	Headers []string        `json:"headers,omitempty"`
	Rows    [][]interface{} `json:"rows,omitempty"`
}

// --- Kubernetes Utilities ---
func executeKubectlCommand(args ...string) ([]byte, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home dir: %w", err)
	}
	kubeconfigPath := filepath.Join(home, ".kube", "config")
	finalArgs := append([]string{"--kubeconfig", kubeconfigPath}, args...)
	cmd := exec.Command("kubectl", finalArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("kubectl %s error: %v, stderr: %s", args[0], err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func applyKubernetesYAML(yamlContent string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlContent)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl apply error: %v, stderr: %s", err, stderr.String())
	}
	return nil
}

func executeKubectlDelete(resourceType, labelSelector string) error {
	_, err := executeKubectlCommand("delete", resourceType, "-l", labelSelector)
	// "not found" はエラーとしない
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return err
	}
	return nil
}

func getKubeConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home dir: %w", err)
	}
	return filepath.Join(home, ".kube", "config"), nil
}

func sanitize(userID string) string {
	sanitized := strings.ToLower(userID)
	reg := regexp.MustCompile("[^a-z0-9-]")
	sanitized = reg.ReplaceAllString(sanitized, "-")
	if len(sanitized) > 40 {
		sanitized = sanitized[:40]
	}
	return sanitized
}

func getServicePorts(labelSelector string) (map[string]int, error) {
	output, err := executeKubectlCommand("get", "services", "-l", labelSelector, "-o", "json")
	if err != nil {
		return nil, err
	}

	ports := make(map[string]int)
	var serviceList struct {
		Items []struct {
			Spec struct {
				Ports []struct {
					Name     string `json:"name"`
					NodePort int    `json:"nodePort"`
				} `json:"ports"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal(output, &serviceList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service list: %w", err)
	}

	for _, item := range serviceList.Items {
		for _, port := range item.Spec.Ports {
			if port.Name != "" {
				ports[port.Name] = port.NodePort
			}
		}
	}
	return ports, nil
}

// --- HTTP Handlers ---
func startExperimentHandler(w http.ResponseWriter, r *http.Request) {
	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.UserID == "" || req.PackageName == "" {
		http.Error(w, "userId and packageName are required", http.StatusBadRequest)
		return
	}

	sanitizedUserID := sanitize(req.UserID)
	log.Printf("Request for user '%s', package '%s'", req.UserID, req.PackageName)

	packageDir := filepath.Join("packages", req.PackageName)
	files, err := os.ReadDir(packageDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("Package '%s' not found", req.PackageName), http.StatusBadRequest)
		return
	}

	var yamlFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".yaml") {
			yamlFiles = append(yamlFiles, file.Name())
		}
	}
	sort.Strings(yamlFiles)

	for _, filename := range yamlFiles {
		log.Printf("Applying: %s", filename)
		yamlPath := filepath.Join(packageDir, filename)
		yamlBytes, err := os.ReadFile(yamlPath)
		if err != nil {
			log.Printf("Failed to read %s: %v", filename, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError); return
		}
		
		replacer := strings.NewReplacer("USER_ID_PLACEHOLDER", sanitizedUserID)
		finalYAML := replacer.Replace(string(yamlBytes))

		if err := applyKubernetesYAML(finalYAML); err != nil {
			log.Printf("Failed to apply %s: %v", filename, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ExperimentResponse{Status:  "error", Message: fmt.Sprintf("Kubernetes設定の適用に失敗しました: %s", err.Error())})
			return
		}
	}
    
    // ▼▼▼ ここに待機処理を追加！ ▼▼▼
	log.Println("Waiting for services to be ready...")
	time.Sleep(5 * time.Second) // 5秒待機
    // ▲▲▲ ここに待機処理を追加！ ▲▲▲

	servicePorts, err := getServicePorts("user-id=" + sanitizedUserID)
	if err != nil {
		// ... (エラーハンドリング)
	}
	publicServicePorts, err := getServicePorts("app=public-minio")
	if err != nil {
		// ... (エラーハンドリング)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExperimentResponse{
		Status:             "success",
		Message:            "Environment is ready.",
		ServicePorts:       servicePorts,
		PublicServicePorts: publicServicePorts,
	})
}

func stopExperimentHandler(w http.ResponseWriter, r *http.Request) {
	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest); return
	}
	if req.UserID == "" {
		http.Error(w, "userId is required", http.StatusBadRequest); return
	}
	sanitizedUserID := sanitize(req.UserID)
	log.Printf("Stopping compute resources for user '%s'", req.UserID)

	labelSelector := "user-id=" + sanitizedUserID
	resourcesToStop := []string{"deployments", "services"}
	for _, resource := range resourcesToStop {
		if err := executeKubectlDelete(resource, labelSelector); err != nil {
			// ... (エラーハンドリング)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExperimentResponse{Status: "success", Message: "Compute resources stopped."})
}

func deleteExperimentHandler(w http.ResponseWriter, r *http.Request) {
	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest); return
	}
	if req.UserID == "" {
		http.Error(w, "userId is required", http.StatusBadRequest); return
	}
	sanitizedUserID := sanitize(req.UserID)
	log.Printf("Deleting ALL resources for user '%s'", req.UserID)

	labelSelector := "user-id=" + sanitizedUserID
	resourcesToDelete := []string{"deployments", "services", "pvc"}
	for _, resource := range resourcesToDelete {
		if err := executeKubectlDelete(resource, labelSelector); err != nil {
			// ... (エラーハンドリング)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExperimentResponse{Status: "success", Message: "All resources deleted."})
}

func executeSQLHandler(w http.ResponseWriter, r *http.Request) {
	var req SQLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest); return
	}
	sanitizedUserID := sanitize(req.UserID)
	
	servicePorts, err := getServicePorts("user-id=" + sanitizedUserID)
	if err != nil || servicePorts["postgres"] == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(SQLResponse{Status:  "error", Message: "Postgres port not found"}); return
	}

	connStr := fmt.Sprintf("postgres://user:mysecretpassword@localhost:%d/testdb", servicePorts["postgres"])
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(SQLResponse{Status:  "error", Message: "データベース接続に失敗しました。コンテナがまだ起動中の可能性があります。少し待ってから再試行してください。"}); return
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(context.Background(), req.SQLQuery)
	if err != nil {
		json.NewEncoder(w).Encode(SQLResponse{Status: "error", Message: err.Error()}); return
	}
	defer rows.Close()

	headers := []string{}
	for _, fd := range rows.FieldDescriptions() {
		headers = append(headers, string(fd.Name))
	}
	results := [][]interface{}{}
	for rows.Next() {
		values, _ := rows.Values()
		results = append(results, values)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SQLResponse{Status: "success", Headers: headers, Rows: results, Message: "Query executed."})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/start-experiment", startExperimentHandler)
	mux.HandleFunc("/stop-experiment", stopExperimentHandler)
	mux.HandleFunc("/delete-experiment", deleteExperimentHandler)
	mux.HandleFunc("/execute-sql", executeSQLHandler)
	
	log.Println("Starting server on port 8000...")
	if err := http.ListenAndServe(":8000", corsMiddleware(mux)); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

