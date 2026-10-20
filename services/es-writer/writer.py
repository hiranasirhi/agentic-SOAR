from opensearchpy import OpenSearch
from config import ELASTIC_HOST, ELASTIC_USER, ELASTIC_PASS, INDEX_NAME

es = OpenSearch(
    hosts=[ELASTIC_HOST],
    http_auth=(ELASTIC_USER, ELASTIC_PASS),
    use_ssl=True,
    verify_certs=False,
)

def write_event(event):
    return es.index(
        index=INDEX_NAME,
        body=event
    )