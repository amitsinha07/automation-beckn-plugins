## FAQs

> **IMPORTANT:** For NP-related queries, always verify the **context** of the subject payload is correct before proceeding with further debugging. Make sure to check the context in a non-workbench-to-workbench environment, as workbench-to-workbench flows most likely won't throw any errors.

### 1. Playground deployment not reflecting changes

- Make sure the config-service is updated correctly.
- Also make sure to clear the playground cache. Replace the domain and version as needed:
    ```bash
    curl --location --request DELETE 'https://dev-automation.ondc.org/mock/ONDC:RET10/1.2.0/backdoor/clear-flows?domain=ONDC%3ARET10' \
    --data
    ```

### 2. Flow is not proceeding at all

- First, check the logs of the mock service.
- If the mock service successfully forwarded the request to the API service, check the API service logs.
- If you can't see logs in either of the above steps, check the `.env` file and verify the deployment of the service.
- The `automation-recorder-service` logs can also be checked to verify writes to DB and cache.

### 3. API calls to workbench are not reflecting in the workbench UI

- Use a new `transaction_id` for every call if the API is the first step in the flow; otherwise, use the same `transaction_id` for the entire flow.
- Make sure you are sending the correct `bap_url` or `bpp_url` in the payload — the one used to create the session in the UI.

### 4. Can't find any error log in mock, and API service did not receive the request

- Most likely the logs got buried under `GET /` request logs from the UI backend.
- If there is an NP API call before the failing step, verify the NP payload carefully and make sure the next generator function won't fail due to missing or incorrect fields in the message.
- Check `Transaction_Session_data` in cache and make sure the requirements for the next step are met.
- The issue is most likely in the generator function for the failing step.
- If nothing else works, try reproducing the issue with Postman or the playground using the NP's payload.

### 5. Where can I view logs and inspect cache for troubleshooting?

- All service logs are available in Dozzle.
- Logs are also available in Grafana (simple-search-dashboard).

### 6. Out of sequence error in workbench

- The payload context contains an incorrect timestamp.
- The NP actually sent incorrect actions.

### 7. Deployment is failing in github actions

- make sure bulid.yaml has correct domain and version in info section.
- make sure the docker image pushed to ghcr.io is public.
- make sure the env variables in github actions are correct.
