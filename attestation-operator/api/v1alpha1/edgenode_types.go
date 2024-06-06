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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type Status string

const (
	Unregistered Status = "unregistered"
	Registered   Status = "registered"
	Unattested   Status = "unattested"
	Attested     Status = "attested"
)

// EdgeNodeSpec defines the desired state of EdgeNode
type EdgeNodeSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	UUID       string `json:"uuid"`
	Status     Status `json:"nodeStatus"`
	EkCert     string `json:"ekcert"`
	MbRefstate string `json:"mbrefstate"`
}

// EdgeNodeStatus defines the observed state of EdgeNode
type EdgeNodeStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// EdgeNode is the Schema for the edgenodes API
type EdgeNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EdgeNodeSpec   `json:"spec,omitempty"`
	Status EdgeNodeStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// EdgeNodeList contains a list of EdgeNode
type EdgeNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeNode `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EdgeNode{}, &EdgeNodeList{})
}
