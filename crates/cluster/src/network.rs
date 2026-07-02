//! In-process raft network: a router that dispatches RPCs directly to the
//! target node's `Raft` handle. This is the transport used for tests and the
//! single-binary demo; a real deployment swaps in an HTTP/gRPC `RaftNetwork`
//! implementing the same three RPCs (append_entries, vote, install_snapshot).

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use openraft::error::{RPCError, RemoteError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, Raft};
use tokio::sync::Mutex;

use crate::types::{NodeId, TypeConfig};

/// Shared registry of the cluster's `Raft` handles, keyed by node id.
#[derive(Clone, Default)]
pub struct Router {
    registry: Arc<Mutex<BTreeMap<NodeId, Raft<TypeConfig>>>>,
}

impl Router {
    /// Register a node's `Raft` handle so peers can reach it.
    pub async fn register(&self, id: NodeId, raft: Raft<TypeConfig>) {
        self.registry.lock().await.insert(id, raft);
    }

    async fn target(&self, id: NodeId) -> Option<Raft<TypeConfig>> {
        self.registry.lock().await.get(&id).cloned()
    }
}

impl RaftNetworkFactory<TypeConfig> for Router {
    type Network = Conn;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        Conn {
            target,
            router: self.clone(),
        }
    }
}

/// A one-peer connection: forwards RPCs to `target` via the router.
pub struct Conn {
    target: NodeId,
    router: Router,
}

impl Conn {
    async fn peer(
        &self,
    ) -> Result<Raft<TypeConfig>, RPCError<NodeId, BasicNode, openraft::error::RaftError<NodeId>>>
    {
        self.router.target(self.target).await.ok_or_else(|| {
            let e = io::Error::new(io::ErrorKind::NotConnected, "peer not in router");
            RPCError::Unreachable(Unreachable::new(&e))
        })
    }
}

impl RaftNetwork<TypeConfig> for Conn {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<NodeId>,
        RPCError<NodeId, BasicNode, openraft::error::RaftError<NodeId>>,
    > {
        let peer = self.peer().await?;
        peer.append_entries(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, openraft::error::RaftError<NodeId>>>
    {
        let peer = self.peer().await?;
        peer.vote(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<
            NodeId,
            BasicNode,
            openraft::error::RaftError<NodeId, openraft::error::InstallSnapshotError>,
        >,
    > {
        let peer = self.router.target(self.target).await.ok_or_else(|| {
            let e = io::Error::new(io::ErrorKind::NotConnected, "peer not in router");
            RPCError::Unreachable(Unreachable::new(&e))
        })?;
        peer.install_snapshot(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}
