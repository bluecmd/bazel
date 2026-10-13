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
import java.util.ArrayDeque;
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
 * same environment. Entries nobody uses are kept for reuse, least recently used first out, up to
 * a limit; environments are only ever reset or closed while no action is using them.
 *
 * <p>With a factory that applies filesystem policies itself ({@link
 * EnvironmentFactory#supportsBlank}), an environment is no longer bound to one policy for its
 * lifetime: it is created blank (no filesystem access), the policy is applied when an action
 * needs it, and cleared again when the entry is evicted, which makes it blank once more. Blank
 * environments are kept in a stock, which a background thread fills up to {@code spares} ahead
 * of demand, so that a new policy costs only its application (about 0.1 ms per path) instead of
 * a {@code CreateProcessSecurityEnvironment} round trip. An action that finds the stock empty
 * creates one itself; {@link #starved} counts how often that happened. Evicted environments always
 * go back into the stock, so a command creates only a bounded number of environments.
 */
final class WindowsPsecEnvironmentPool {

  /** Creates and closes environments. */
  interface EnvironmentFactory {
    /** An environment with exactly the policy of {@code spec}. */
    long create(Spec spec) throws IOException;

    void close(long handle);

    /** Whether {@link #createBlank}, {@link #apply} and {@link #clear} are supported. */
    default boolean supportsBlank() {
      return false;
    }

    /** An environment with {@code spec}'s network setting and no filesystem access. */
    default long createBlank(boolean allowNetwork) throws IOException {
      throw new UnsupportedOperationException();
    }

    /** Applies {@code spec}'s paths to a blank environment. */
    default void apply(long handle, Spec spec) throws IOException {
      throw new UnsupportedOperationException();
    }

    /** Removes all paths from an environment, making it blank again. */
    default void clear(long handle) throws IOException {
      throw new UnsupportedOperationException();
    }
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

    /** Whether the environment was set up for this lease rather than reused. */
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
  private final boolean blank;
  private final int spares;
  private final Map<Spec, Entry> entries = new HashMap<>();
  // Unused entries, least recently used first.
  private final LinkedHashSet<Entry> idle = new LinkedHashSet<>();
  // Blank environments, by network setting (index 1 = network allowed).
  @SuppressWarnings("unchecked")
  private final ArrayDeque<Long>[] stock = new ArrayDeque[] {new ArrayDeque<>(), new ArrayDeque<>()};
  private boolean closed;
  private Thread refiller;

  /** Policies set up (a new environment, or a blank one with the policy applied). */
  final AtomicLong creates = new AtomicLong();

  /** Actions that found an environment with their policy. */
  final AtomicLong reuses = new AtomicLong();

  /** Time spent setting up policies, including any inline creation. */
  final AtomicLong createNanos = new AtomicLong();

  final AtomicLong createdPaths = new AtomicLong();

  /** Policies set up on a blank environment from the stock. */
  final AtomicLong fromStock = new AtomicLong();

  /** Policies that found the stock empty and had to create a blank environment inline. */
  final AtomicLong starved = new AtomicLong();

  /** Time spent creating blank environments inline because the stock was empty. */
  final AtomicLong starvedNanos = new AtomicLong();

  /** Blank environments created by the background thread. */
  final AtomicLong refilled = new AtomicLong();

  /** Evicted environments that were cleared and put back into the stock. */
  final AtomicLong recycled = new AtomicLong();

  /** Time actions spent in {@link #acquire}, including waiting for others' creations. */
  final AtomicLong acquireNanos = new AtomicLong();

  final AtomicLong maxAcquireNanos = new AtomicLong();

  WindowsPsecEnvironmentPool(EnvironmentFactory factory, int maxIdle) {
    this(factory, maxIdle, 0);
  }

  /**
   * @param spares blank environments to keep ready (only with a factory that {@link
   *     EnvironmentFactory#supportsBlank}); evicted environments are then cleared into the stock
   *     instead of closed
   */
  WindowsPsecEnvironmentPool(EnvironmentFactory factory, int maxIdle, int spares) {
    this.factory = factory;
    this.maxIdle = maxIdle;
    this.blank = factory.supportsBlank();
    this.spares = blank ? spares : 0;
  }

  /** Returns an environment for `spec`, creating one if none exists. */
  Lease acquire(Spec spec) throws IOException, InterruptedException {
    long start = System.nanoTime();
    try {
      return doAcquire(spec);
    } finally {
      long took = System.nanoTime() - start;
      acquireNanos.addAndGet(took);
      maxAcquireNanos.accumulateAndGet(took, Math::max);
    }
  }

  private Lease doAcquire(Spec spec) throws IOException, InterruptedException {
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
        entry.handle = blank ? setUp(spec) : factory.create(spec);
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

  /** A blank environment from the stock (or a new one) with `spec` applied. */
  private long setUp(Spec spec) throws IOException {
    int net = spec.allowNetwork() ? 1 : 0;
    Long handle;
    synchronized (this) {
      handle = stock[net].poll();
      if (spares > 0) {
        // Started on first use: commands that run no sandboxed action create nothing.
        if (refiller == null) {
          refiller = new Thread(this::refill, "windows-psec-refill");
          refiller.setDaemon(true);
          refiller.start();
        }
        notifyAll(); // wake the refiller
      }
    }
    if (handle != null) {
      fromStock.incrementAndGet();
    } else {
      long start = System.nanoTime();
      handle = factory.createBlank(spec.allowNetwork());
      starvedNanos.addAndGet(System.nanoTime() - start);
      starved.incrementAndGet();
    }
    try {
      factory.apply(handle, spec);
    } catch (IOException | RuntimeException e) {
      factory.close(handle);
      throw e;
    }
    return handle;
  }

  /** Keeps the no-network stock at `spares`. */
  private void refill() {
    while (true) {
      synchronized (this) {
        while (!closed && stock[0].size() >= spares) {
          try {
            wait();
          } catch (InterruptedException e) {
            return;
          }
        }
        if (closed) {
          return;
        }
      }
      long handle;
      try {
        handle = factory.createBlank(false);
      } catch (IOException | RuntimeException e) {
        // Actions create their own and report the error; retry later.
        synchronized (this) {
          try {
            wait(1000);
          } catch (InterruptedException ie) {
            return;
          }
        }
        continue;
      }
      boolean keep;
      synchronized (this) {
        keep = !closed;
        if (keep) {
          stock[0].add(handle);
        }
      }
      if (keep) {
        refilled.incrementAndGet();
      } else {
        factory.close(handle);
      }
    }
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
      retire(e.handle, e.spec.allowNetwork());
    }
  }

  /**
   * Clears an unused environment back into the stock. Environments are never closed before the
   * pool is: every {@code CreateProcessSecurityEnvironment} leaks a logon session in Windows (about
   * 64 K per boot), so the pool creates as few as it can, at most about the peak number of
   * concurrent actions plus {@code maxIdle} plus {@code spares} per command.
   */
  private void retire(long handle, boolean allowNetwork) {
    int net = allowNetwork ? 1 : 0;
    boolean open;
    synchronized (this) {
      open = spares > 0 && !closed;
    }
    if (open) {
      try {
        factory.clear(handle);
        synchronized (this) {
          if (!closed) {
            stock[net].add(handle);
            recycled.incrementAndGet();
            return;
          }
        }
      } catch (IOException | RuntimeException e) {
        // Close it instead.
      }
    }
    factory.close(handle);
  }

  /** Number of environments currently set up for a policy. */
  synchronized int size() {
    return entries.size();
  }

  /** Number of blank environments ready for use. */
  synchronized int stockSize() {
    return stock[0].size() + stock[1].size();
  }

  /**
   * Closes every environment. Only call this when no action runs any more, e.g. at the end of a
   * command.
   */
  void close() {
    List<Entry> all;
    List<Long> blanks = new ArrayList<>();
    Thread t;
    synchronized (this) {
      closed = true;
      notifyAll();
      t = refiller;
      all = new ArrayList<>(entries.values());
      entries.clear();
      idle.clear();
      for (ArrayDeque<Long> s : stock) {
        blanks.addAll(s);
        s.clear();
      }
    }
    if (t != null) {
      try {
        t.join(10_000);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    for (Entry e : all) {
      if (e.created.isDone() && e.handle != 0) {
        factory.close(e.handle);
      }
    }
    for (long h : blanks) {
      factory.close(h);
    }
  }
}
