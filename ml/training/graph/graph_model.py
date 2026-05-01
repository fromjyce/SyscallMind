"""Program-Syscall-Resource tripartite graph model using GraphSAGE-style convolutions."""
import random
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor


class GraphSAGEConv(nn.Module):
    """Mean-aggregation GraphSAGE layer (no external dependency on PyG)."""

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.linear = nn.Linear(in_dim * 2, out_dim)

    def forward(self, x: Tensor, edge_index: Tensor) -> Tensor:
        """
        Args:
            x: Node feature matrix [N, in_dim]
            edge_index: Edge indices [2, E] — row 0 = source, row 1 = target
        Returns:
            Updated node features [N, out_dim]
        """
        src, dst = edge_index[0], edge_index[1]
        num_nodes = x.size(0)

        # Aggregate neighbor features (mean pooling)
        agg = torch.zeros(num_nodes, x.size(1), device=x.device)
        counts = torch.zeros(num_nodes, 1, device=x.device)
        agg.scatter_add_(0, src.unsqueeze(1).expand(-1, x.size(1)), x[dst])
        counts.scatter_add_(0, src.unsqueeze(1), torch.ones(src.size(0), 1, device=x.device))
        counts = counts.clamp(min=1)
        agg = agg / counts

        combined = torch.cat([x, agg], dim=1)
        return F.relu(self.linear(combined))


class ProgramSyscallGraph(nn.Module):
    """Two-layer GraphSAGE over the program-syscall-resource tripartite graph."""

    def __init__(self, num_nodes: int, embed_dim: int = 64):
        super().__init__()
        self.embedding = nn.Embedding(num_nodes, embed_dim)
        self.conv1 = GraphSAGEConv(embed_dim, embed_dim)
        self.conv2 = GraphSAGEConv(embed_dim, embed_dim)
        self.norm = nn.LayerNorm(embed_dim)

    def forward(self, edge_index: Tensor) -> Tensor:
        num_nodes = self.embedding.num_embeddings
        node_ids = torch.arange(num_nodes, device=edge_index.device)
        x = self.embedding(node_ids)
        x = self.conv1(x, edge_index)
        x = self.conv2(x, edge_index)
        return self.norm(x)


class GraphDataset:
    """Generates synthetic tripartite graph samples for link prediction training."""

    def __init__(
        self,
        num_programs: int = 100,
        num_syscalls: int = 256,
        num_resources: int = 50,
        num_samples: int = 1000,
    ):
        self.num_programs = num_programs
        self.num_syscalls = num_syscalls
        self.num_resources = num_resources
        self.num_samples = num_samples
        # Node index offsets: programs [0..P), syscalls [P..P+S), resources [P+S..P+S+R)
        self.p_offset = 0
        self.s_offset = num_programs
        self.r_offset = num_programs + num_syscalls
        self.total_nodes = num_programs + num_syscalls + num_resources

    def generate_sample(self) -> dict:
        """Generate a random transaction subgraph with program→syscall and syscall→resource edges."""
        program = random.randint(0, self.num_programs - 1) + self.p_offset
        num_calls = random.randint(2, 10)
        edges_src, edges_dst = [], []
        for _ in range(num_calls):
            syscall = random.randint(0, self.num_syscalls - 1) + self.s_offset
            edges_src.append(program)
            edges_dst.append(syscall)
            resource = random.randint(0, self.num_resources - 1) + self.r_offset
            edges_src.append(syscall)
            edges_dst.append(resource)
        edge_index = torch.tensor([edges_src, edges_dst], dtype=torch.long)
        return {"edge_index": edge_index, "program_node": program, "num_calls": num_calls}

    def __len__(self) -> int:
        return self.num_samples

    def __iter__(self):
        for _ in range(self.num_samples):
            yield self.generate_sample()
