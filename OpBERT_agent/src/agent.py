import forta_agent
import numpy as np
import rlp
from forta_agent import get_json_rpc_url
from web3 import Web3
import torch as tc
from pyevmasm import disassemble_hex
from transformers import DistilBertTokenizerFast
from transformers import DistilBertForSequenceClassification
from transformers.utils import logging
import warnings
from src.findings import MaliciousContractFindings
from src.logger import logger

logging.set_verbosity_error()
warnings.filterwarnings("ignore")

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
model = None
tokenizer = None
device = 'cpu'


def initialize():
    """
    this function loads the ml model.
    """

    global tokenizer, model
    model = DistilBertForSequenceClassification.from_pretrained("distilbert-base-uncased")
    model.load_state_dict(tc.load("./src/opcodes_model_weights.pth", map_location=tc.device('cpu')))
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    model.eval()
    logger.info("Model loaded successfully")


def detect_malicious_contract_tx(
        w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    all_findings = []

    if len(transaction_event.traces) > 0:
        for trace in transaction_event.traces:
            if trace.type == "create":
                created_contract_address = (
                    trace.result.address if trace.result else None
                )
                error = trace.error if trace.error else None
                logger.info(f"Contract created {created_contract_address}")
                if error is not None:
                    nonce = (
                        transaction_event.transaction.nonce
                        if transaction_event.from_ == trace.action.from_
                        else 1
                    )  # for contracts creating other contracts, the nonce would be 1. WARN: this doesn't handle create2 tx
                    contract_address = calc_contract_address(
                        w3, trace.action.from_, nonce
                    )
                    logger.info(
                        f"Contract {contract_address} creation failed with tx {trace.transactionHash}: {error}"
                    )
                all_findings.extend(
                    detect_malicious_contract(
                        w3,
                        trace.action.from_,
                        created_contract_address,
                    )
                )
    else:  # Trace isn't supported, To improve coverage, process contract creations from EOAs.
        if transaction_event.to is None:
            nonce = transaction_event.transaction.nonce
            created_contract_address = calc_contract_address(
                w3, transaction_event.from_, nonce
            )

            all_findings.extend(
                detect_malicious_contract(
                    w3,
                    transaction_event.from_,
                    created_contract_address,
                )
            )

    return all_findings


def detect_malicious_contract(w3, from_, created_contract_address) -> list:
    print('detecting...')
    global tokenizer
    findings = []

    if created_contract_address is not None:
        print("getting code")
        bytecode = w3.eth.get_code(Web3.toChecksumAddress(created_contract_address)).hex()
        opcodes = disassemble_hex(bytecode)
        print(opcodes)

        inputs = tokenizer([opcodes], padding="max_length", truncation=True)
        item = {key: tc.tensor(val[0]) for key, val in inputs.items()}
        input_ids = tc.tensor(item["input_ids"]).to(device)
        attention_mask = tc.tensor(item["attention_mask"]).to(device)
        with tc.no_grad():
            outputs = model(input_ids.unsqueeze(0), attention_mask.unsqueeze(0))

        print(outputs)
        logger.info(f'Result scores: {outputs}')
        y = np.argmax(outputs[0].to('cpu').numpy())

        if y == 1:
            findings.append(
                MaliciousContractFindings.malicious_contract_detected(
                    from_,
                    created_contract_address,
                )
            )

    return findings


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def provide_handle_transaction(w3):
    def handle_transaction(
            transaction_event: forta_agent.transaction_event.TransactionEvent,
    ) -> list:
        try:
            return detect_malicious_contract_tx(w3, transaction_event)
        except Exception as e:
            print(e)
            return []

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(
        transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
