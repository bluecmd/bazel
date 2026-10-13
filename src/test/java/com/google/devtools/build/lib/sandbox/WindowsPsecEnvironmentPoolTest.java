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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableList;
import com.google.devtools.build.lib.sandbox.WindowsPsecPolicyBuilder.Spec;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link WindowsPsecEnvironmentPool}. */
@RunWith(JUnit4.class)
public final class WindowsPsecEnvironmentPoolTest {

  private static class FakeFactory implements WindowsPsecEnvironmentPool.EnvironmentFactory {
    final AtomicLong next = new AtomicLong(100);
    final List<Long> created = new ArrayList<>();
    final List<Long> closed = new ArrayList<>();
    CountDownLatch gate = new CountDownLatch(0);
    boolean fail;

    @Override
    public long create(Spec spec) throws IOException {
      try {
        gate.await();
      } catch (InterruptedException e) {
        throw new IOException(e);
      }
      if (fail) {
        throw new IOException("boom");
      }
      long h = next.getAndIncrement();
      synchronized (this) {
        created.add(h);
      }
      return h;
    }

    @Override
    public synchronized void close(long handle) {
      closed.add(handle);
    }
  }

  private static Spec spec(String ro) {
    return new Spec(
        ImmutableList.of("C:\\out"),
        ImmutableList.of(ro),
        ImmutableList.of(),
        ImmutableList.of("C:\\"),
        false);
  }

  @Test
  public void samePolicySharesOneEnvironment() throws Exception {
    FakeFactory factory = new FakeFactory();
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 4);

    WindowsPsecEnvironmentPool.Lease a = pool.acquire(spec("C:\\a"));
    WindowsPsecEnvironmentPool.Lease b = pool.acquire(spec("C:\\a"));
    WindowsPsecEnvironmentPool.Lease c = pool.acquire(spec("C:\\c"));

    assertThat(a.handle()).isEqualTo(b.handle());
    assertThat(a.created()).isTrue();
    assertThat(b.created()).isFalse();
    assertThat(c.handle()).isNotEqualTo(a.handle());
    assertThat(factory.created).hasSize(2);
    assertThat(pool.reuses.get()).isEqualTo(1);

    a.release();
    a.release(); // Idempotent.
    b.release();
    // Idle, but kept for reuse.
    assertThat(factory.closed).isEmpty();
    assertThat(pool.acquire(spec("C:\\a")).handle()).isEqualTo(100);
  }

  @Test
  public void idleEnvironmentsBeyondTheLimitAreClosedOldestFirst() throws Exception {
    FakeFactory factory = new FakeFactory();
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 1);

    WindowsPsecEnvironmentPool.Lease a = pool.acquire(spec("C:\\a"));
    WindowsPsecEnvironmentPool.Lease b = pool.acquire(spec("C:\\b"));
    a.release();
    assertThat(factory.closed).isEmpty();
    b.release();
    assertThat(factory.closed).containsExactly(a.handle());
    assertThat(pool.size()).isEqualTo(1);

    pool.close();
    assertThat(factory.closed).containsExactly(a.handle(), b.handle());
    assertThrows(IOException.class, () -> pool.acquire(spec("C:\\a")));
  }

  @Test
  public void concurrentAcquiresOfANewPolicyCreateOnce() throws Exception {
    FakeFactory factory = new FakeFactory();
    factory.gate = new CountDownLatch(1);
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 4);
    ExecutorService executor = Executors.newFixedThreadPool(8);
    try {
      List<Future<WindowsPsecEnvironmentPool.Lease>> leases = new ArrayList<>();
      for (int i = 0; i < 16; i++) {
        leases.add(executor.submit(() -> pool.acquire(spec("C:\\x"))));
      }
      Thread.sleep(100);
      factory.gate.countDown();
      for (Future<WindowsPsecEnvironmentPool.Lease> f : leases) {
        assertThat(f.get(10, TimeUnit.SECONDS).handle()).isEqualTo(100);
      }
      assertThat(factory.created).containsExactly(100L);
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void failedCreationIsReportedAndRetried() throws Exception {
    FakeFactory factory = new FakeFactory();
    factory.fail = true;
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 4);

    IOException e = assertThrows(IOException.class, () -> pool.acquire(spec("C:\\a")));
    assertThat(e).hasMessageThat().isEqualTo("boom");
    assertThat(pool.size()).isEqualTo(0);

    factory.fail = false;
    assertThat(pool.acquire(spec("C:\\a")).created()).isTrue();
  }

  /** A factory with client-side policies: blank environments, apply and clear. */
  private static final class BlankFactory extends FakeFactory {
    final List<String> log = new ArrayList<>();
    CountDownLatch blankGate = new CountDownLatch(0);

    @Override
    public boolean supportsBlank() {
      return true;
    }

    @Override
    public long createBlank(boolean allowNetwork) throws IOException {
      try {
        blankGate.await();
      } catch (InterruptedException e) {
        throw new IOException(e);
      }
      long h = next.getAndIncrement();
      synchronized (this) {
        created.add(h);
        log.add("blank " + h);
      }
      return h;
    }

    @Override
    public synchronized void apply(long handle, Spec spec) {
      log.add("apply " + handle + " " + spec.readOnly().get(0));
    }

    @Override
    public synchronized void clear(long handle) {
      log.add("clear " + handle);
    }

    synchronized boolean logged(String line) {
      return log.contains(line);
    }
  }

  @Test
  public void withoutSparesEveryNewPolicyCreatesInlineAndCountsAsStarved() throws Exception {
    BlankFactory factory = new BlankFactory();
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 4, 0);

    WindowsPsecEnvironmentPool.Lease a = pool.acquire(spec("C:\\a"));
    WindowsPsecEnvironmentPool.Lease b = pool.acquire(spec("C:\\a"));

    assertThat(a.handle()).isEqualTo(b.handle());
    assertThat(factory.log).containsExactly("blank 100", "apply 100 C:\\a").inOrder();
    assertThat(pool.starved.get()).isEqualTo(1);
    assertThat(pool.fromStock.get()).isEqualTo(0);
    assertThat(pool.reuses.get()).isEqualTo(1);
  }

  @Test
  public void sparesAreCreatedAheadAndUsedForNewPolicies() throws Exception {
    BlankFactory factory = new BlankFactory();
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 4, 2);

    // The first policy starts the refiller and finds the stock empty.
    WindowsPsecEnvironmentPool.Lease a = pool.acquire(spec("C:\\a"));
    assertThat(pool.starved.get()).isEqualTo(1);
    waitFor(() -> pool.stockSize() == 2);

    WindowsPsecEnvironmentPool.Lease b = pool.acquire(spec("C:\\b"));
    assertThat(pool.fromStock.get()).isEqualTo(1);
    assertThat(pool.starved.get()).isEqualTo(1);
    assertThat(b.handle()).isNotEqualTo(a.handle());
    assertThat(factory.logged("apply " + b.handle() + " C:\\b")).isTrue();
    // ... and the refiller tops the stock up again.
    waitFor(() -> pool.stockSize() == 2);
    assertThat(pool.refilled.get()).isEqualTo(3);

    a.release();
    b.release();
    pool.close();
    assertThat(factory.closed).containsExactlyElementsIn(factory.created);
  }

  @Test
  public void evictedEnvironmentsAreClearedAndRecycledForOtherPolicies() throws Exception {
    BlankFactory factory = new BlankFactory();
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 0, 1);

    WindowsPsecEnvironmentPool.Lease a = pool.acquire(spec("C:\\a"));
    long handleA = a.handle();
    waitFor(() -> pool.stockSize() == 1);
    // maxIdle = 0: releasing evicts the entry. Even with the stock full it is cleared and kept,
    // not closed.
    a.release();
    assertThat(factory.logged("clear " + handleA)).isTrue();
    assertThat(factory.closed).isEmpty();
    assertThat(pool.stockSize()).isEqualTo(2);
    assertThat(pool.recycled.get()).isEqualTo(1);

    // New policies use the stock; nothing new needs creating.
    int created = factory.created.size();
    WindowsPsecEnvironmentPool.Lease b = pool.acquire(spec("C:\\b"));
    WindowsPsecEnvironmentPool.Lease c = pool.acquire(spec("C:\\c"));
    assertThat(factory.logged("apply " + b.handle() + " C:\\b")).isTrue();
    assertThat(factory.logged("apply " + c.handle() + " C:\\c")).isTrue();
    assertThat(java.util.List.of(b.handle(), c.handle())).contains(handleA);
    b.release();
    c.release();
    assertThat(pool.starved.get()).isEqualTo(1); // Only the very first policy.
    pool.close();
    assertThat(factory.closed).containsExactlyElementsIn(factory.created);
    assertThat(factory.created.size()).isAtMost(created + 2);
  }

  @Test
  public void aCommandCreatesBoundedEnvironments() throws Exception {
    BlankFactory factory = new BlankFactory();
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 4, 2);
    ExecutorService executor = Executors.newFixedThreadPool(8);
    try {
      List<Future<?>> done = new ArrayList<>();
      for (int i = 0; i < 400; i++) {
        String p = "C:\\p" + i;
        done.add(
            executor.submit(
                () -> {
                  pool.acquire(spec(p)).release();
                  return null;
                }));
      }
      for (Future<?> f : done) {
        f.get(10, TimeUnit.SECONDS);
      }
    } finally {
      executor.shutdownNow();
    }
    // 400 distinct policies, at most 8 at a time: in use + idle + spares + refiller slack.
    assertThat(factory.created.size()).isAtMost(8 + 4 + 2 + 2);
    assertThat(factory.closed).isEmpty();
    pool.close();
    assertThat(factory.closed).containsExactlyElementsIn(factory.created);
  }

  @Test
  public void sparesAreIgnoredWithoutBlankSupport() throws Exception {
    FakeFactory factory = new FakeFactory();
    WindowsPsecEnvironmentPool pool = new WindowsPsecEnvironmentPool(factory, 4, 8);
    pool.acquire(spec("C:\\a")).release();
    assertThat(factory.created).containsExactly(100L);
    assertThat(pool.stockSize()).isEqualTo(0);
    assertThat(pool.starved.get()).isEqualTo(0);
  }

  private static void waitFor(java.util.function.BooleanSupplier condition) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("timed out");
      }
      Thread.sleep(5);
    }
  }
}
