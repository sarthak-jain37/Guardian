import io,json,subprocess,tarfile,tempfile,unittest
from pathlib import Path
from scripts.guardian_release import bundle


class ReleaseBundleTests(unittest.TestCase):
    def test_bundle_contains_committed_source_and_checksums_but_no_ignored_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'repo';root.mkdir()
            def git(*args):return subprocess.run(['git',*args],cwd=root,check=True,capture_output=True)
            git('init');git('config','user.email','test@example.invalid');git('config','user.name','Fixture Author')
            (root/'.gitignore').write_text('data/\n.env\n');(root/'main.py').write_text('print("example")\n')
            git('add','.');git('commit','-m','source')
            (root/'data').mkdir();(root/'data/private.token').write_text('not for release');(root/'.env').write_text('SECRET=test')
            output=Path(temp)/'candidate.tgz';result=bundle(output,root=root)
            with tarfile.open(output) as tar:
                self.assertEqual(set(tar.getnames()),{'.gitignore','main.py','candidate-manifest.json'})
                manifest=json.load(tar.extractfile('candidate-manifest.json'))
                self.assertEqual(manifest['source_commit'],result['source_commit']);self.assertIn('main.py',manifest['files'])
            (root/'main.py').write_text('changed')
            with self.assertRaisesRegex(ValueError,'clean'):bundle(Path(temp)/'dirty.tgz',root=root)
