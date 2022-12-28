from forta_agent import Finding, FindingType, FindingSeverity


class MaliciousContractFindings:

    @staticmethod
    def malicious_contract_detected(from_address: str, contract_address: str) -> Finding:
        # metadata = {"address_contained_in_created_contract_" + str(i): address for i, address in enumerate(contained_addresses, 1)}
        # metadata["model_score"] = str(model_score)
        # metadata["model_threshold"] = str(model_threshold)

        return Finding({
            'name': 'Malicious Contract Detected',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'MCD-SouCoBERT-ALERT',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Critical,
            # 'metadata': metadata
        })


    @staticmethod
    def unable_to_decompile(from_address: str, contract_address: str) -> Finding:

        return Finding({
            'name': 'Contract Decompilation error',
            'description': f'Unable to decompile {contract_address} created by {from_address}',
            'alert_id': 'MCD-SouCoBERT-ERROR',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
        })
