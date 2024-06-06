package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"

	edgenode "gitlab.ilabt.imec.be/edge-keylime/attestation-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ResponseData struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Results struct {
		AikTPM   string `json:"aik_tpm"`
		EkTPM    string `json:"ek_tpm"`
		EkCert   string `json:"ekcert"`
		MtlsCert string `json:"mtls_cert"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		RegCount int    `json:"regcount"`
	} `json:"results"`
}

func AuthenticateEdgeNode(ctx context.Context, clientset *kubernetes.Clientset, edgenode *edgenode.EdgeNode) error {
	//contact registrar to get TPM ID
	service, err := clientset.CoreV1().Services("keylime").Get(ctx, "hhkl-keylime-registrar", metav1.GetOptions{})
	if err != nil {
		return err
	}
	serviceIP := service.Spec.ClusterIP
	var servicePort int32
	for _, port := range service.Spec.Ports {
		if port.Name == "registrar-tls" {
			servicePort = port.Port
			break
		}
	}

	url := fmt.Sprintf("https://%s:%d/v2.1/agents/%s", serviceIP, servicePort, edgenode.Spec.UUID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	cert, err := tls.LoadX509KeyPair("/var/lib/controller/certs/csr.crt", "/var/lib/controller/certs/csr.key")
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		//this is temp for this PoC, the keylime ca does not include kubernetes internal hostname
		InsecureSkipVerify: true,
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("registrar request error")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var responseData ResponseData
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return err
	}

	//check that EKCert provided by sysadmin in CR matches the one provided by the registrar
	//registrar does the crypto validation of the cert for us, if the registrar provides it, we can assume that the node proved its identity related to this cert
	fmt.Println(edgenode.Spec.EkCert)
	fmt.Println(responseData.Results.EkCert)
	if edgenode.Spec.EkCert != responseData.Results.EkCert {
		return errors.New("unable to validate TPM identity")
	}

	return nil

}

func DeployFledge(ctx context.Context, clientset *kubernetes.Clientset, pKeyPEM *[]byte, certPEM *[]byte, edgenode *edgenode.EdgeNode) error {

	err, zipBuffer := packageZIP(pKeyPEM, certPEM)
	if err != nil {
		return err
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	zipPart, err := writer.CreateFormFile("file", "file")
	if err != nil {
		return err
	}

	_, err = zipPart.Write(zipBuffer)
	if err != nil {
		return err
	}

	err = writer.WriteField("uuid", edgenode.Spec.UUID)
	if err != nil {
		panic(err)
	}

	jsonPart, err := writer.CreateFormFile("json", "json")
	if err != nil {
		return err
	}
	_, err = jsonPart.Write([]byte(edgenode.Spec.MbRefstate))
	if err != nil {
		return err
	}

	writer.Close()

	service, err := clientset.CoreV1().Services("keylime").Get(ctx, "hhkl-keylime-tenant", metav1.GetOptions{})
	if err != nil {
		return err
	}
	serviceIP := service.Spec.ClusterIP
	var servicePort int32
	for _, port := range service.Spec.Ports {
		if port.Name == "tenant" {
			servicePort = port.Port
			break
		}
	}

	url := fmt.Sprintf("http://%s:%d/edgenode", serviceIP, servicePort)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New("unexpected response from tenant: " + resp.Status)
	}

	return nil
}

func packageZIP(pKeyPEM *[]byte, certPEM *[]byte) (err error, zipBuffer []byte) {

	var buf bytes.Buffer

	zipWriter := zip.NewWriter(&buf)

	defer zipWriter.Close()

	certWriter, err := zipWriter.Create("cert.pem")
	if err != nil {
		return err, nil
	}
	_, err = certWriter.Write(*certPEM)
	if err != nil {
		return err, nil
	}

	keyWriter, err := zipWriter.Create("key.pem")
	if err != nil {
		return err, nil
	}
	_, err = keyWriter.Write(*pKeyPEM)
	if err != nil {
		return err, nil
	}

	runScript, err := os.ReadFile("autorun.sh")
	if err != nil {
		return err, nil
	}
	runWriter, err := zipWriter.Create("autorun.sh")
	if err != nil {
		return err, nil
	}
	_, err = runWriter.Write(runScript)
	if err != nil {
		return err, nil
	}

	err = zipWriter.Close()
	if err != nil {
		return err, nil
	}
	return nil, buf.Bytes()
}
