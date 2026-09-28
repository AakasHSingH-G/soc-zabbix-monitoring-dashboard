const crypto = require('crypto');

function createJobQueue({ concurrency = 1, maximum = 5 } = {}) {
  const jobs = new Map();
  const pending = [];
  let running = 0;
  let queueMaximum = maximum;

  function snapshot() {
    return { pending: pending.length, running, maximum: queueMaximum };
  }

  function pump() {
    while (running < concurrency && pending.length) {
      const job = pending.shift();
      if (job.status !== 'queued') continue;
      running += 1;
      job.status = 'running';
      job.startedAt = new Date().toISOString();
      Promise.resolve().then(() => job.run(job.controller.signal)).then(result => {
        if (job.status === 'running') {
          job.result = result;
          job.status = 'completed';
        }
      }).catch(error => {
        job.error = error.name === 'AbortError' ? 'Analysis cancelled.' : (error.message || 'Analysis failed.');
        job.status = error.name === 'AbortError' ? 'cancelled' : 'failed';
      }).finally(() => {
        job.finishedAt = new Date().toISOString();
        running -= 1;
        try { job.onSettled?.(job); } catch {}
        pump();
      });
    }
  }

  function enqueue({ ip, username, run, onSettled }) {
    if (pending.length + running >= queueMaximum) return { error: 'AI queue is full', status: 429 };
    const job = {
      id: crypto.randomUUID(), ip, username, run, onSettled,
      status: 'queued', createdAt: new Date().toISOString(),
      controller: new AbortController(), result: null, error: null,
    };
    jobs.set(job.id, job);
    if (jobs.size > 250) {
      for (const [oldId, oldJob] of jobs) {
        if (!['queued', 'running'].includes(oldJob.status)) jobs.delete(oldId);
        if (jobs.size <= 200) break;
      }
    }
    pending.push(job);
    pump();
    return { job };
  }

  function get(jobId) {
    return jobs.get(jobId) || null;
  }

  function cancel(jobId, reason = 'Cancelled by analyst') {
    const job = get(jobId);
    if (!job || ['completed', 'failed', 'cancelled'].includes(job.status)) return false;
    job.status = 'cancelled';
    job.error = reason;
    job.controller.abort();
    pump();
    return true;
  }

  function cancelAll(reason = 'AI deactivated') {
    for (const job of jobs.values()) {
      if (['queued', 'running'].includes(job.status)) cancel(job.id, reason);
    }
  }

  function setMaximum(value) {
    queueMaximum = value;
  }

  function all() {
    return [...jobs.values()].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  return { enqueue, get, cancel, cancelAll, setMaximum, snapshot, all };
}

module.exports = { createJobQueue };
