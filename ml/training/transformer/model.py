import math
import torch
import torch.nn as nn
from torch import Tensor
from torch.utils.data import Dataset


class SyscallTransformer(nn.Module):
    """Decoder-only Transformer for next-syscall prediction."""

    def __init__(
        self,
        vocab_size: int = 256,
        embed_dim: int = 128,
        num_heads: int = 4,
        num_layers: int = 4,
        max_seq_len: int = 64,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embed_dim = embed_dim
        self.max_seq_len = max_seq_len

        self.token_emb = nn.Embedding(vocab_size, embed_dim)
        self.pos_emb = nn.Embedding(max_seq_len, embed_dim)

        decoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=dropout,
            batch_first=True,
        )
        self.transformer = nn.TransformerEncoder(decoder_layer, num_layers=num_layers)
        self.norm = nn.LayerNorm(embed_dim)
        self.head = nn.Linear(embed_dim, vocab_size)

        self._init_weights()

    def _init_weights(self):
        nn.init.normal_(self.token_emb.weight, std=0.02)
        nn.init.normal_(self.pos_emb.weight, std=0.02)
        nn.init.normal_(self.head.weight, std=0.02)
        nn.init.zeros_(self.head.bias)

    def _causal_mask(self, seq_len: int, device: torch.device) -> Tensor:
        mask = torch.triu(torch.ones(seq_len, seq_len, device=device), diagonal=1).bool()
        return mask

    def forward(self, x: Tensor) -> Tensor:
        B, T = x.shape
        positions = torch.arange(T, device=x.device).unsqueeze(0).expand(B, -1)
        h = self.token_emb(x) + self.pos_emb(positions)
        mask = self._causal_mask(T, x.device)
        h = self.transformer(h, mask=mask)
        h = self.norm(h)
        return self.head(h)


class SyscallDataset(Dataset):
    """Sliding-window dataset over syscall ID sequences."""

    def __init__(self, sequences: list, max_len: int = 64):
        self.max_len = max_len
        self.samples: list = []
        for seq in sequences:
            if len(seq) < 2:
                continue
            # Create overlapping windows
            for start in range(0, max(1, len(seq) - 1)):
                end = min(start + max_len + 1, len(seq))
                window = seq[start:end]
                if len(window) >= 2:
                    self.samples.append(window)

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int):
        seq = self.samples[idx]
        ids = torch.tensor(seq, dtype=torch.long)
        # Pad to max_len + 1
        pad_len = self.max_len + 1 - len(ids)
        if pad_len > 0:
            ids = torch.cat([ids, torch.zeros(pad_len, dtype=torch.long)])
        ids = ids[: self.max_len + 1]
        return ids[:-1], ids[1:]  # input, target


def create_model(vocab_size: int = 256) -> SyscallTransformer:
    return SyscallTransformer(vocab_size=vocab_size)
