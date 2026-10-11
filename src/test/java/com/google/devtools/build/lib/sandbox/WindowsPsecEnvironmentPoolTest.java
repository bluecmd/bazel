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

  private static final class FakeFactory implements WindowsPsecEnvironmentPool.EnvironmentFactory {
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
}
