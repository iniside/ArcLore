package lore

import (
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc"

	thin_clientv1 "arcloreweb/gen/lore/thin_client/v1"
)

// drainRevisionTree drains a RevisionTree server-stream. The first message is
// expected to carry the Header oneof variant; every subsequent message carries
// a TreeNode. It returns the resolved header plus the accumulated nodes.
//
// The stream's context is the caller's (cancelled on client disconnect); Recv
// returns the context error in that case, which is surfaced to the caller.
func drainRevisionTree(
	stream grpc.ServerStreamingClient[thin_clientv1.RevisionTreeResponse],
) (*thin_clientv1.RevisionTreeHeader, []*thin_clientv1.TreeNode, error) {
	var header *thin_clientv1.RevisionTreeHeader
	nodes := make([]*thin_clientv1.TreeNode, 0)
	first := true

	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return header, nodes, nil
		}
		if err != nil {
			return header, nodes, err
		}

		switch payload := msg.Payload.(type) {
		case *thin_clientv1.RevisionTreeResponse_Header:
			if !first {
				return header, nodes, fmt.Errorf("lore: RevisionTree header out of order")
			}
			header = payload.Header
		case *thin_clientv1.RevisionTreeResponse_Node:
			nodes = append(nodes, payload.Node)
		default:
			return header, nodes, fmt.Errorf("lore: RevisionTree unexpected payload %T", msg.Payload)
		}
		first = false
	}
}

// RevisionDiffEntry is one body element of a RevisionDiff stream: exactly one
// of Change / Conflict is non-nil. Exported so the handlers-package LoreClient
// interface can name RevisionDiff's return type.
type RevisionDiffEntry struct {
	Change   *thin_clientv1.DiffChange
	Conflict *thin_clientv1.DiffConflict
}

// drainRevisionDiff drains a RevisionDiff server-stream. The first message is
// the Header; subsequent messages are DiffChange or DiffConflict items.
func drainRevisionDiff(
	stream grpc.ServerStreamingClient[thin_clientv1.RevisionDiffResponse],
) (*thin_clientv1.RevisionDiffHeader, []RevisionDiffEntry, error) {
	var header *thin_clientv1.RevisionDiffHeader
	entries := make([]RevisionDiffEntry, 0)
	first := true

	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return header, entries, nil
		}
		if err != nil {
			return header, entries, err
		}

		switch payload := msg.Payload.(type) {
		case *thin_clientv1.RevisionDiffResponse_Header:
			if !first {
				return header, entries, fmt.Errorf("lore: RevisionDiff header out of order")
			}
			header = payload.Header
		case *thin_clientv1.RevisionDiffResponse_Change:
			entries = append(entries, RevisionDiffEntry{Change: payload.Change})
		case *thin_clientv1.RevisionDiffResponse_Conflict:
			entries = append(entries, RevisionDiffEntry{Conflict: payload.Conflict})
		default:
			return header, entries, fmt.Errorf("lore: RevisionDiff unexpected payload %T", msg.Payload)
		}
		first = false
	}
}
