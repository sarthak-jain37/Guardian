"""Build a private-data-free candidate source bundle from a clean committed tree."""
import argparse,hashlib,io,json,subprocess,tarfile
from pathlib import Path,PurePosixPath
from datetime import datetime,timezone


def bundle(output,slides=None,*,root=None):
    root=Path(root or Path(__file__).resolve().parents[1]);output=Path(output)
    def git(*args):return subprocess.check_output(['git',*args],cwd=root)
    if git('status','--porcelain').strip():raise ValueError('candidate_bundle_requires_clean_committed_tree')
    if output.exists():raise ValueError('release_destination_exists')
    commit=git('rev-parse','HEAD').decode().strip();archive=git('archive','--format=tar','HEAD')
    manifest={'schema_version':'guardian.candidate-bundle.v1','source_commit':commit,'status':'release_candidate_external_acceptance_pending',
        'created_at':datetime.now(timezone.utc).isoformat(),'files':{},'live_lab_acceptance':False}
    output.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as source,tarfile.open(output,mode='w:gz') as target:
        for member in source.getmembers():
            name=PurePosixPath(member.name)
            if member.isdir():continue
            if (not member.isfile() or name.is_absolute() or '..' in name.parts or name.parts[0] in ('data','personal_docs','.git')
                    or name.name=='.env' or name.name.endswith(('.token','.auth.json','.archive-keys.json'))):
                raise ValueError('private_or_unsafe_file_in_tracked_release')
            data=source.extractfile(member).read();target.addfile(member,io.BytesIO(data));manifest['files'][member.name]=hashlib.sha256(data).hexdigest()
        if slides:
            slides=Path(slides);data=slides.read_bytes();info=tarfile.TarInfo('docs/guardian-demo.pptx');info.size=len(data);info.mode=0o644
            target.addfile(info,io.BytesIO(data));manifest['files'][info.name]=hashlib.sha256(data).hexdigest()
        data=json.dumps(manifest,indent=2).encode();info=tarfile.TarInfo('candidate-manifest.json');info.size=len(data);info.mode=0o644;target.addfile(info,io.BytesIO(data))
    with output.open('rb') as f:checksum=hashlib.file_digest(f,'sha256').hexdigest()
    output.with_suffix(output.suffix+'.sha256').write_text(checksum+'  '+output.name+'\n')
    return {'source_commit':commit,'artifact':str(output),'sha256':checksum,'files':len(manifest['files']),'status':manifest['status']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--slides',type=Path)
    a=p.parse_args();print(json.dumps(bundle(a.output,a.slides),indent=2))


if __name__=='__main__':main()
