# Kubernetes-master

[Kubernetes](http://kubernetes.io/) is an open source system for managing
application containers across a cluster of hosts. The Kubernetes project was
started by Google in 2014, combining the experience of running production
workloads combined with best practices from the community.

The Kubernetes project defines some new terms that may be unfamiliar to users
or operators. For more information please refer to the concept guide in the
[getting started guide](https://kubernetes.io/docs/home/).

This charm is an encapsulation of the Kubernetes master processes and the
operations to run on any cloud for the entire lifecycle of the cluster.

This charm is built from other charm layers using the Juju reactive framework.
The other layers focus on specific subset of operations making this layer
specific to operations of Kubernetes master processes.

This charm is a component of Charmed Kubernetes. For full information,
please visit the [official Charmed Kubernetes docs](https://www.ubuntu.com/kubernetes/docs/charm-kuberenetes-master).
