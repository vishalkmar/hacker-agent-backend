// Phase 3 (buckets) unit tests. Run: node scripts/test-buckets.mjs
import { spawnSync } from 'node:child_process';
import { buildBucketCommand, bucketKeywords, parseBucketReport, extractBucketFindings, renderBuckets } from '../src/services/buckets/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n + keyword permutations');
for (const b of ['iamalive.app', 'iamalive.app deep', 'acme.com seed:acmecorp', 'cloud_enum -k acme']) {
  const cmd = buildBucketCommand(b);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${b}"`, r.status === 0, r.stderr?.trim());
}
ok('raw passthrough', buildBucketCommand('cloud_enum -k acme') === 'cloud_enum -k acme');
const fast = bucketKeywords('iamalive.app', null, { deep: false });
const deep = bucketKeywords('iamalive.app', null, { deep: true });
ok('fast <= 60, deep > fast', fast.length <= 60 && deep.length > fast.length, `${fast.length}/${deep.length}`);
ok('includes base + permutations', fast.includes('iamalive') && fast.includes('iamalive-assets') && fast.includes('iamalivebackup'));
ok('seed keyword included', bucketKeywords('acme.com', 'acmecorp', { deep: false }).some((k) => k.startsWith('acmecorp')));
ok('names bucket-name valid (3-63)', deep.every((k) => k.length >= 3 && k.length <= 63));
ok('deep parallelizes s3+gcs+azure+do', /echo "azure /.test(buildBucketCommand('x.com deep')) && /echo "do /.test(buildBucketCommand('x.com deep')));
ok('fast is s3+gcs only', !/echo "azure /.test(buildBucketCommand('x.com')) && /xargs -P/.test(buildBucketCommand('x.com')));

console.log('\n[2] BUCKETFIND parsing + classification');
const rep = [
  '== bucket enum ==',
  `BUCKETFIND${T}high${T}s3${T}PUBLIC S3 bucket is world-listable: acme-assets${T}objects: a.jpg,b.pdf,${T}https://acme-assets.s3.amazonaws.com/`,
  `BUCKETFIND${T}low${T}gcs${T}GCS bucket exists but is private: acme${T}HTTP 403 / AccessDenied${T}https://storage.googleapis.com/acme/`,
  `BUCKETFIND${T}high${T}azure${T}PUBLIC Azure blob container is listable: acme${T}acme.blob.core.windows.net${T}https://acme.blob.core.windows.net/acme?...`,
].join('\n');
const f = parseBucketReport(rep);
ok('3 findings', f.length === 3, `got ${f.length}`);
ok('all finding_type=storage', f.every((x) => x.finding_type === 'storage'));
ok('public S3 = high + service s3', f[0].severity === 'high' && f[0].service === 's3');
ok('public remediation says make private', /make the bucket.*private|Block Public Access/i.test(f[0].remediation));
ok('private bucket = low', f[1].severity === 'low');
ok('host carries the URL', f[0].host === 'https://acme-assets.s3.amazonaws.com/');

console.log('\n[3] extractor + render');
ok('extractor routes on BUCKETFIND', extractBucketFindings('buckets x', rep).length === 3);
ok('extractor inert otherwise', extractBucketFindings('ls', '{}').length === 0);
const r = renderBuckets(rep);
ok('render splits public vs private sections', /Public \/ listable/i.test(r) && /Existing \(private\)/i.test(r));
ok('render empty -> friendly msg', /No public or private storage buckets/.test(renderBuckets('nothing')));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '⚠️  FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
