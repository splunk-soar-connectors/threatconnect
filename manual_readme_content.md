[comment]: # " File: README.md"
[comment]: # "     Copyright (c) 2016-2025 Splunk Inc."
[comment]: # "     Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "     you may not use this file except in compliance with the License."
[comment]: # "     You may obtain a copy of the License at"
[comment]: #
[comment]: # "       http://www.apache.org/licenses/LICENSE-2.0"
[comment]: #
[comment]: # "     Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "     the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "     either express or implied. See the License for the specific language governing permissions"
[comment]: # "     and limitations under the License."
[comment]: #

## Playbook Backward Compatibility

- In version 3.0.0 of the connector, the API endpoints were updated from V2 to V3. Additionally, below three new parameters were added to the actions **'hunt ip', 'hunt file', 'hunt email', 'hunt domain',** and **'hunt url'**:

  - **attribute** - Retrieves Indicator attributes (default: **false**).
  - **tag** - Retrieves Indicator tags (default: **false**).
  - **security label** - Retrieves Indicator security labels (default: **false**).

- As a result, the output data paths have been updated. To ensure your existing playbooks function correctly, please **update, reinsert, modify, or delete** the affected action blocks accordingly.

### Asset Configuration Update

- The **base_url** parameter in the asset configuration should be set according to your ThreatConnect instance. Examples:

  - `https://api.threatconnect.com`
  - `https://sandbox.threatconnect.com`
  - `https://companyabc.threatconnect.com/api`

- For more details, please refer to the [ThreatConnect API documentation](https://docs.threatconnect.com/en/latest/rest_api/quick_start.html?utm_source=chatgpt.com#using-the-api).
