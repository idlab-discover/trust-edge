package controller

import (
	"context"
	"errors"

	edgenode "gitlab.ilabt.imec.be/edge-keylime/attestation-operator/api/v1alpha1"
	"k8s.io/client-go/kubernetes"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	certificatesv1 "k8s.io/api/certificates/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ObtainUserAccount(ctx context.Context, clientset *kubernetes.Clientset, edgeNode *edgenode.EdgeNode) (pKeyPEM []byte, certPEM []byte, err error) {

	//create csr, also returns generated private key
	csr, pKeyPEM, err := createCertificateSigningRequest(ctx, clientset, edgeNode)
	if err != nil {
		return nil, nil, err
	}

	//approve csr, also returns generated certificate
	certPEM, err = approveCertificateSigningRequest(ctx, clientset, csr)
	if err != nil {
		return nil, nil, err
	}

	//create clusterrole and clusterrolebinding for edge node
	createUserAccount(ctx, clientset, edgeNode, certPEM, pKeyPEM)

	return pKeyPEM, certPEM, err

}

func createCertificateSigningRequest(ctx context.Context, clientset *kubernetes.Clientset, edgeNode *edgenode.EdgeNode) (*certificatesv1.CertificateSigningRequest, []byte, error) {
	l := log.FromContext(ctx)
	csrName := edgeNode.Spec.UUID + "-csr"

	// check if the CSR already exists
	csr, err := clientset.CertificatesV1().CertificateSigningRequests().Get(context.Background(), csrName, metav1.GetOptions{})
	if err == nil {
		l.Info("CSR already exists, continue", "Name", csr.Name, "Status", csr.Status.Conditions)
		return nil, nil, errors.New("CSR already exists")
	}
	l.Info("Creating CSR", "Name", csr.Name, "Status", csr.Status.Conditions)

	//create csr
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return csr, nil, err
	}

	pKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			//Organization: []string{"discover.idlab"},
			CommonName: edgeNode.Spec.UUID,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return csr, pKeyPEM, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	csr = &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request: csrPEM,
			Usages: []certificatesv1.KeyUsage{
				certificatesv1.UsageDigitalSignature,
				certificatesv1.UsageKeyEncipherment,
				certificatesv1.UsageClientAuth,
			},
			SignerName: "kubernetes.io/kube-apiserver-client",
		},
	}
	//push csr to K8s API
	csr, err = clientset.CertificatesV1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})

	return csr, pKeyPEM, err
}

func approveCertificateSigningRequest(ctx context.Context, clientset *kubernetes.Clientset, csr *certificatesv1.CertificateSigningRequest) ([]byte, error) {
	l := log.FromContext(ctx)
	//check if already approved
	if csr.Status.Conditions != nil && csr.Status.Conditions[0].Type == certificatesv1.CertificateApproved {
		l.Info("CSR already approved, continue", "Name", csr.Name, "Status", csr.Status.Conditions)
		return nil, nil
	}

	//approve
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:           certificatesv1.CertificateApproved,
		Reason:         "EdgeNodeControllerApproval",
		Message:        "Node passed identity checks and was automatically issues this certificate",
		LastUpdateTime: metav1.Now(),
		Status:         "True",
	})

	//push approval to K8s API
	csr, err := clientset.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	// wait for csr to be available
	var certPEM []byte
	for certPEM == nil {
		time.Sleep(100 * time.Millisecond)
		csr, err = clientset.CertificatesV1().CertificateSigningRequests().Get(context.Background(), csr.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		certPEM = csr.Status.Certificate
	}

	//certificate has been obtained, delete csr to keep everything clean
	err = clientset.CertificatesV1().CertificateSigningRequests().Delete(ctx, csr.Name, metav1.DeleteOptions{})
	if err != nil {
		return nil, err
	}

	return certPEM, err

}

func createUserAccount(ctx context.Context, clientset *kubernetes.Clientset, edgenode *edgenode.EdgeNode, certPEM []byte, pKeyPEM []byte) error {
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: edgenode.Spec.UUID + "-cluster-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	}
	clusterRole, err := clientset.RbacV1().ClusterRoles().Create(context.Background(), clusterRole, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: edgenode.Spec.UUID + "-cluster-role-binding",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "User",
				Name:      edgenode.Spec.UUID,
				Namespace: "default",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: clusterRole.Name,
		},
	}
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(context.Background(), clusterRoleBinding, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil

}
