"""Real provider transport/schema smoke test. No cluster or evaluation labels."""
import argparse
import json
from pathlib import Path
from pydantic import BaseModel,ConfigDict
from agents.guardian.modeling import load_profile
from agents.guardian.runner import configured_model


class SmokeAnswer(BaseModel):
    model_config=ConfigDict(extra='forbid')
    status:str
    missing_evidence_establishes_safety:bool


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--profile',type=Path,default=Path('agents/guardian/config/dev-laptop.toml'))
    args=parser.parse_args(argv)
    config=load_profile(args.profile).model_copy(update={'max_output_tokens':256})
    model,_=configured_model(config.model_dump(mode='json'))
    try:
        result=model.generate('investigator',[{'role':'system','content':'Return only the requested JSON. Missing evidence does not establish safety.'},
            {'role':'user','content':'Set status to ok and missing_evidence_establishes_safety to false.'}],
            SmokeAnswer.model_json_schema(),config,timeout_seconds=config.request_timeout_seconds)
        answer=SmokeAnswer.model_validate(result.response) if result.error is None else None
        passed=answer is not None and answer.status=='ok' and answer.missing_evidence_establishes_safety is False
        print(json.dumps({'scope':'real_model_transport_schema_smoke_only','passed':passed,
            'model':result.requested_model,'resolved_model':result.resolved_model,'resolved_revision':result.resolved_revision,
            'error':result.error,'duration_seconds':round(result.duration_seconds,3),
            'input_tokens':result.input_tokens,'output_tokens':result.output_tokens,'cluster_writes':False},indent=2))
        return 0 if passed else 1
    finally:model.close()


if __name__=='__main__':raise SystemExit(main())
