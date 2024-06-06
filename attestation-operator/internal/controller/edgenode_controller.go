/*
Copyright 2024 jthijsma.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"time"

	//"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	edgenode "gitlab.ilabt.imec.be/edge-keylime/attestation-operator/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"

	"k8s.io/client-go/rest"
	//"k8s.io/client-go/tools/clientcmd"
)

// EdgeNodeReconciler reconciles a EdgeNode object
type EdgeNodeReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// RBAC for EdgeNode
//+kubebuilder:rbac:groups=edgenode.attest.idlab.be,resources=edgenodes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=edgenode.attest.idlab.be,resources=edgenodes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=edgenode.attest.idlab.be,resources=edgenodes/finalizers,verbs=update

// RBAC for creating CSR
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=create;get;list;watch;delete

// RBAC for approving CSR
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=approve;update
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=approve,resourceNames=kubernetes.io/kube-apiserver-client

// RBAC for comms with cloud components
//+kubebuilder:rbac:groups="",resources=services;secrets;serviceaccounts,verbs=get;list;create;patch
//+kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=clusterroles;clusterrolebindings,verbs=get;list;create;patch;update
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the EdgeNode object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.0/pkg/reconcile

func (r *EdgeNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	edgeNode := &edgenode.EdgeNode{}

	if err := r.Get(ctx, req.NamespacedName, edgeNode); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	//use kubeconfig for testing locally, use incluster for testing and deployment in K8s
	//config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("HOME")+"/.kube/config")
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	ref, err := reference.GetReference(r.Scheme, edgeNode)
	if err != nil {
		return ctrl.Result{Requeue: false}, err
	}

	switch edgeNode.Spec.Status {
	case edgenode.Unregistered:
		r.Recorder.Eventf(ref, v1.EventTypeNormal, "EdgeNodeUnregistered", "Edgenode resource was added but has not been registered with the registrar yet")
		l.Info("Unregistered node", "uuid", edgeNode.Spec.UUID)
		if err != nil {
			return ctrl.Result{Requeue: false}, err
		}
		return ctrl.Result{Requeue: false}, nil
	case edgenode.Registered:
		r.Recorder.Eventf(ref, v1.EventTypeNormal, "EdgeNodeRegistered", "Edgenode was registered by the registrar")
		l.Info("Registered node", "uuid", edgeNode.Spec.UUID)
		//registered, needs credentials

		err = AuthenticateEdgeNode(ctx, clientset, edgeNode)
		if err != nil {
			//failed to authenticate node, try again later (node might not have connected yet)
			l.Error(err, "Failed to authenticate node", "Node UUID", edgeNode.Spec.UUID, "Node Status", edgeNode.Spec.Status)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, err
		}

		pKeyPEM, certPEM, err := ObtainUserAccount(ctx, clientset, edgeNode)
		if err != nil {
			return ctrl.Result{Requeue: false}, err
		}

		//pass private key, signed certificate and ca information to fledge (after attestation)
		err = DeployFledge(ctx, clientset, &pKeyPEM, &certPEM, edgeNode)

		if err != nil {
			return ctrl.Result{Requeue: false}, err
		}

		return ctrl.Result{Requeue: false}, nil

	case edgenode.Unattested:
		r.Recorder.Eventf(ref, v1.EventTypeWarning, "EdgeNodeUnattested", "Edgenode failed attesation")
		l.Info("Unattested node", "uuid", edgeNode.Spec.UUID)
		//not attested, take action
		clusterRole, err := clientset.RbacV1().ClusterRoles().Get(context.TODO(), edgeNode.Spec.UUID+"-cluster-role", metav1.GetOptions{})
		if err != nil {
			panic(err.Error())
		}

		// remove all permissions
		clusterRole.Rules = []rbacv1.PolicyRule{}

		_, err = clientset.RbacV1().ClusterRoles().Update(context.TODO(), clusterRole, metav1.UpdateOptions{})
		if err != nil {
			return ctrl.Result{Requeue: false}, err
		}
		return ctrl.Result{Requeue: false}, nil

	case edgenode.Attested:
		r.Recorder.Eventf(ref, v1.EventTypeNormal, "EdgeNodeAttested", "Edgenode is attested")
		//attested, do nothing, do not requeue
		l.Info("Attested node", "uuid", edgeNode.Spec.UUID)
		return ctrl.Result{Requeue: false}, nil

	}

	return ctrl.Result{Requeue: false}, errors.New("invalid node state for node " + edgeNode.Spec.UUID)
}

// SetupWithManager sets up the controller with the Manager.
func (r *EdgeNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&edgenode.EdgeNode{}).
		Complete(r)
}
