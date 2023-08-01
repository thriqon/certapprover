package main

import (
	"context"
	"flag"
	"os"

	cm_v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cm_meta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"k8s.io/apimachinery/pkg/runtime"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	events "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type CertApprover struct {
	client.Client

	Policy        *ast.Compiler
	EventRecorder events.EventRecorder
}

func (ca *CertApprover) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	cr := &cm_v1.CertificateRequest{}
	err := ca.Get(ctx, req.NamespacedName, cr)
	if err != nil {
		// TODO: logging?
		return ctrl.Result{}, err
	}

	if ca.certificateRequestIsDecided(cr.Status) {
		log.Info("skipping certificateRequest, as it is decided already")

		return ctrl.Result{}, nil
	}

	namespace := &corev1.Namespace{}
	err = ca.Get(ctx, types.NamespacedName{Name: req.NamespacedName.Namespace}, namespace)
	if err != nil {
		log.Error(err, "unable to get namespace")

		return ctrl.Result{}, err
	}

	input := map[string]interface{}{
		"object": cr,
		"namespace": namespace,
	}

	r := rego.New(
		rego.Compiler(ca.Policy),
		rego.Package("approval"),
		rego.Input(input),
		rego.Query("allow"))

	rs, err := r.Eval(ctx)
	if err != nil {
		log.Info("Error during policy evalution", "error", err)

		return ctrl.Result{}, err
	}

	log.Info("Policy evalution result", "resultset", rs)
	if rs.Allowed() {
		err := ca.approve(ctx, cr)
		if err != nil {
			log.Error(err, "unable to approve certificate request")
			ca.EventRecorder.Event(cr, "Warning", "Approval", "Unable to approve policy, even though accepted by policy")

			return ctrl.Result{}, err
		}

		ca.EventRecorder.Event(cr, "Normal", "Approval", "Accepted by policy")

		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (ca *CertApprover) certificateRequestIsDecided(crs cm_v1.CertificateRequestStatus) bool {
	for _, con := range crs.Conditions {
		if con.Status == cm_meta.ConditionTrue &&
			(con.Type == cm_v1.CertificateRequestConditionApproved ||
				con.Type == cm_v1.CertificateRequestConditionDenied) {
			return true
		}
	}

	return false
}

func (ca *CertApprover) approve(ctx context.Context, cr *cm_v1.CertificateRequest) error {
 transitionTime := metav1.Now()
	patch := &cm_v1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: cr.GetNamespace(), Name: cr.GetName()},
		Status: cm_v1.CertificateRequestStatus{
			Conditions: []cm_v1.CertificateRequestCondition{
    cm_v1.CertificateRequestCondition{
				  Type:               "Approved",
				  Status:             "True",
				  LastTransitionTime: &transitionTime,
				  Reason:             "certapprover",
				  Message:            "CertificateRequest has been approved by certapprover",
    },
			},
		},
	}

	return ca.Status().Patch(ctx, cr, client.StrategicMergeFrom(patch))
}

func (ca *CertApprover) findObjectsForNamespace(ctx context.Context, namespace client.Object) []reconcile.Request {
	log := ctrl.LoggerFrom(ctx)

	certificateRequests := &cm_v1.CertificateRequestList{}
	if err := ca.List(ctx, certificateRequests, &client.ListOptions{
		Namespace: namespace.GetName(),
	}); err != nil {
		log.Error(err, "unable to retrieve associated certificate requests for namespace", "namespace", namespace)

		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, len(certificateRequests.Items))
	for i, item := range certificateRequests.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      item.GetName(),
				Namespace: item.GetNamespace(),
			},
		}
	}

	log.Info("enqueuing requests for objects due to namespace change", "namespace", namespace, "objects", requests)

	return requests
}

func main() {
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	ctx := ctrl.SetupSignalHandler()

	log := ctrl.Log.WithName("certapprover")

	remainings := flag.Args()
	if len(remainings) == 0 {
		log.Info("no policy loaded, exit early")
		os.Exit(0)
	}

	moduleSources := make(map[string]string)
	for _, policyFile := range remainings {
		bs, err := os.ReadFile(policyFile)
		if err != nil {
			log.Error(err, "unable to read policy file", "filename", policyFile)
			os.Exit(1)
		}

		moduleSources[policyFile] = string(bs)
	}

	pol, err := ast.CompileModules(moduleSources)
	if err != nil {
		log.Error(err, "unable to compile policy")
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(cm_v1.AddToScheme(scheme))

	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "could not create manager")
		os.Exit(1)
	}

	certApprover := CertApprover{
		Client:        manager.GetClient(),
		Policy:        pol,
		EventRecorder: manager.GetEventRecorderFor("certapprover"),
	}

	err = ctrl.
		NewControllerManagedBy(manager).
		For(&cm_v1.CertificateRequest{}).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(certApprover.findObjectsForNamespace),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(&certApprover)
	if err != nil {
		log.Error(err, "could not create controller for certificaterequests")
		os.Exit(1)
	}

	if err := manager.Start(ctx); err != nil {
		log.Error(err, "could not start manager")
		os.Exit(1)
	}

	log.Info("completed")
}
