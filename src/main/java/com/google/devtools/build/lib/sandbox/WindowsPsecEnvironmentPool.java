// Copyright 2026 The Bazel Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.devtools.build.lib.sandbox;

import com.google.common.util.concurrent.SettableFuture;
import com.google.devtools.build.lib.sandbox.WindowsPsecPolicyBuilder.Spec;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Process security environments, one per distinct policy, shared by all actions that need that
 * policy.
 *
 * <p>An environment can be attached to any number of processes at the same time, so an entry is
 * shared rather than handed out exclusively: concurrent actions with the same policy run in the
 * same environment. Creating an environment costs about 30 ms plus about 1 ms per path, which is
 * what this saves. Entries nobody uses are kept for reuse, least recently used first out, up to a
 * limit; environments are only ever closed while no action is using them.
 */
final class WindowsPsecEnvironmentPool {

  /** Creates and closes environments. */
  interface EnvironmentFactory {
    long create(Spec spec) throws IOException;

    void close(long handle);
  }

  /** The use of an environment by one action. */
  final class Lease {
    private final Entry entry;
    private boolean released;

    private Lease(Entry entry) {
      this.entry = entry;
    }

    long handle() {
      return entry.handle;
    }

    /** Whether the environment was created for this lease rather than reused. */
    boolean created() {
      return entry.creator == this;
    }

    void release() {
      synchronized (WindowsPsecEnvironmentPool.this) {
        if (released) {
          return;
        }
        released = true;
      }
      WindowsPsecEnvironmentPool.this.release(entry);
    }
  }

  private static final class Entry {
    final Spec spec;
    final SettableFuture<Long> created = SettableFuture.create();
    long handle;
    int users;
    Lease creator;

    Entry(Spec spec) {
      this.spec = spec;
    }
  }

  private final EnvironmentFactory factory;
  private final int maxIdle;
  private final Map<Spec, Entry> entries = new HashMap<>();
  // Unused entries, least recently used first.
  private final LinkedHashSet<Entry> idle = new LinkedHashSet<>();
  private boolean closed;

  final AtomicLong creates = new AtomicLong();
  final AtomicLong reuses = new AtomicLong();
  final AtomicLong createNanos = new AtomicLong();
  final AtomicLong createdPaths = new AtomicLong();

  WindowsPsecEnvironmentPool(EnvironmentFactory factory, int maxIdle) {
    this.factory = factory;
    this.maxIdle = maxIdle;
  }

  /** Returns an environment for `spec`, creating one if none exists. */
  Lease acquire(Spec spec) throws IOException, InterruptedException {
    Entry entry;
    Lease lease;
    boolean create;
    synchronized (this) {
      if (closed) {
        throw new IOException("windows-psec: the environment pool is closed");
      }
      entry = entries.get(spec);
      create = entry == null;
      if (create) {
        entry = new Entry(spec);
        entries.put(spec, entry);
      }
      entry.users++;
      idle.remove(entry);
      lease = new Lease(entry);
      if (create) {
        entry.creator = lease;
      }
    }
    if (create) {
      long start = System.nanoTime();
      try {
        entry.handle = factory.create(spec);
      } catch (IOException | RuntimeException e) {
        synchronized (this) {
          entries.remove(spec);
        }
        entry.created.setException(e);
        throw e;
      }
      createNanos.addAndGet(System.nanoTime() - start);
      createdPaths.addAndGet(spec.pathCount());
      creates.incrementAndGet();
      entry.created.set(entry.handle);
      return lease;
    }
    try {
      entry.created.get();
    } catch (ExecutionException e) {
      synchronized (this) {
        entry.users--;
      }
      throw new IOException(e.getCause().getMessage(), e.getCause());
    } catch (InterruptedException e) {
      release(entry);
      throw e;
    }
    reuses.incrementAndGet();
    return lease;
  }

  private void release(Entry entry) {
    List<Entry> evicted = new ArrayList<>();
    synchronized (this) {
      entry.users--;
      if (entry.users > 0 || !entry.created.isDone() || entries.get(entry.spec) != entry) {
        return;
      }
      idle.add(entry);
      while (idle.size() > maxIdle) {
        Entry oldest = idle.iterator().next();
        idle.remove(oldest);
        entries.remove(oldest.spec);
        evicted.add(oldest);
      }
    }
    for (Entry e : evicted) {
      factory.close(e.handle);
    }
  }

  /** Number of environments currently open. */
  synchronized int size() {
    return entries.size();
  }

  /**
   * Closes every environment. Only call this when no action runs any more, e.g. at the end of a
   * command.
   */
  void close() {
    List<Entry> all;
    synchronized (this) {
      closed = true;
      all = new ArrayList<>(entries.values());
      entries.clear();
      idle.clear();
    }
    for (Entry e : all) {
      if (e.created.isDone() && e.handle != 0) {
        factory.close(e.handle);
      }
    }
  }
}
