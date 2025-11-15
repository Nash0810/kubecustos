package k8s

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"golang.org/x/sync/singleflight"
)

// PodCache is a thread-safe, Informer-based cache for mapping ContainerIDs to Pods.
type PodCache struct {
	client         kubernetes.Interface
	nodeName       string
	informer       cache.SharedIndexInformer
	store          cache.Store
	containerCache map[string]*v1.Pod
	cacheLock      sync.RWMutex

	// singleflight group to dedupe API fallback lookups per containerID
	sf singleflight.Group
}

// NewPodCache creates a new Informer-based PodCache.
// It sets up an informer that only watches pods scheduled to this node.
func NewPodCache(client kubernetes.Interface, nodeName string) *PodCache {
	factory := informers.NewSharedInformerFactoryWithOptions(
		client,
		30*time.Minute, // resync period
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = "spec.nodeName=" + nodeName
		}),
	)

	podInformer := factory.Core().V1().Pods().Informer()

	pc := &PodCache{
		client:         client,
		nodeName:       nodeName,
		informer:       podInformer,
		store:          podInformer.GetStore(),
		containerCache: make(map[string]*v1.Pod),
	}

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    pc.onAdd,
		UpdateFunc: pc.onUpdate,
		DeleteFunc: pc.onDelete,
	})

	return pc
}

// Run starts the informer and waits for it to sync.
// Returns true if sync is successful, false otherwise.
func (pc *PodCache) Run(ctx context.Context) bool {
	go pc.informer.Run(ctx.Done())
	return cache.WaitForCacheSync(ctx.Done(), pc.informer.HasSynced)
}

// FindPodByContainerID returns the Pod for the given container ID.
// Steps:
//  1) fast map lookup
//  2) scan informer's store (local, cheap)
//  3) optional API fallback (limited to this node) guarded by singleflight to avoid thundering
func (pc *PodCache) FindPodByContainerID(containerID string) *v1.Pod {
	if containerID == "" {
		return nil
	}

	// 1) Fast path: map
	pc.cacheLock.RLock()
	if pod, ok := pc.containerCache[containerID]; ok {
		pc.cacheLock.RUnlock()
		return pod
	}
	pc.cacheLock.RUnlock()

	// 2) Scan informer's local store
	items := pc.store.List()
	for _, obj := range items {
		pod, ok := obj.(*v1.Pod)
		if !ok || pod == nil {
			continue
		}
		for _, status := range pod.Status.ContainerStatuses {
			parts := strings.Split(status.ContainerID, "://")
			if len(parts) == 2 && parts[1] == containerID {
				// populate cache and return
				pc.cacheLock.Lock()
				pc.containerCache[containerID] = pod
				pc.cacheLock.Unlock()
				return pod
			}
			// also handle docker likes that may contain "sha256:<id>"
			if len(parts) == 2 && strings.HasPrefix(parts[1], "sha256:") {
				if strings.TrimPrefix(parts[1], "sha256:") == containerID {
					pc.cacheLock.Lock()
					pc.containerCache[containerID] = pod
					pc.cacheLock.Unlock()
					return pod
				}
			}
		}
	}

	// 3) API fallback (singleflight guarded) - list pods on this node only
	if pc.client == nil {
		return nil
	}

	v, err, _ := pc.sf.Do(containerID, func() (interface{}, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// narrow the list by node to keep payload small
		opts := metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + pc.nodeName,
		}
		podList, err := pc.client.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for i := range podList.Items {
			pod := &podList.Items[i]
			for _, status := range pod.Status.ContainerStatuses {
				parts := strings.Split(status.ContainerID, "://")
				if len(parts) == 2 && parts[1] == containerID {
					// update in-memory cache so future lookups are fast
					pc.cacheLock.Lock()
					pc.containerCache[containerID] = pod
					pc.cacheLock.Unlock()
					return pod, nil
				}
				if len(parts) == 2 && strings.HasPrefix(parts[1], "sha256:") {
					if strings.TrimPrefix(parts[1], "sha256:") == containerID {
						pc.cacheLock.Lock()
						pc.containerCache[containerID] = pod
						pc.cacheLock.Unlock()
						return pod, nil
					}
				}
			}
		}
		// not found
		return nil, nil
	})
	if err != nil {
		// API failure; log once per id would be ideal, but keep minimal
		log.Printf("podcache: API fallback failed for containerID %s: %v", containerID, err)
		return nil
	}
	if pod, _ := v.(*v1.Pod); pod != nil {
		return pod
	}

	// not found
	return nil
}

// --- event handlers and helpers ---

func (pc *PodCache) onAdd(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return
	}
	pc.updatePod(pod)
}

func (pc *PodCache) onUpdate(oldObj, newObj interface{}) {
	pod, ok := newObj.(*v1.Pod)
	if !ok {
		return
	}
	pc.updatePod(pod)
}

func (pc *PodCache) onDelete(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			return
		}
	}
	pc.deletePod(pod)
}

func (pc *PodCache) updatePod(pod *v1.Pod) {
	pc.cacheLock.Lock()
	defer pc.cacheLock.Unlock()

	for _, status := range pod.Status.ContainerStatuses {
		parts := strings.Split(status.ContainerID, "://")
		if len(parts) == 2 {
			containerID := parts[1]
			// normalize sha256: prefix
			if strings.HasPrefix(containerID, "sha256:") {
				containerID = strings.TrimPrefix(containerID, "sha256:")
			}
			pc.containerCache[containerID] = pod
		}
	}
}

func (pc *PodCache) deletePod(pod *v1.Pod) {
	pc.cacheLock.Lock()
	defer pc.cacheLock.Unlock()

	for _, status := range pod.Status.ContainerStatuses {
		parts := strings.Split(status.ContainerID, "://")
		if len(parts) == 2 {
			containerID := parts[1]
			if strings.HasPrefix(containerID, "sha256:") {
				containerID = strings.TrimPrefix(containerID, "sha256:")
			}
			delete(pc.containerCache, containerID)
		}
	}
}
