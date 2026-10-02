from research_data.sources.taxii import TaxiiSourceAdapter


class FakeConfiguredAdapter:
    source_name = "configured-taxii"

    def fetch_objects(self, collection_id, *, added_after=None):
        return []


def test_taxii_extension_contract_is_structural_and_does_not_claim_live_access():
    assert isinstance(FakeConfiguredAdapter(), TaxiiSourceAdapter)
