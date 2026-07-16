# Recovery snapshots

This directory is reserved for exceptional emergency-recovery snapshots that
cannot be represented by a tag or commit.

Previous filesystem copies were removed from the active tree because Git
history already preserves them and several created unsafe path lengths on
Windows. New development must not target a snapshot directory.
