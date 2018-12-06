# Azure Audit (Pre-release draft, lots of updates to come)

Azure Audit logs events to OMS based on rules as defined below.  The specific rules Azure Audit tracks will expand over time and will potentially encompass many more rules than this inital version which is primarily focused on custom RBAC assignment and their association with Azure subscriptions.

## Pre-Requisites

1. Azure Active Directory(AAD) service principle. (to add: MSI, permission requirments)
2. Azure Key Vault (to add: keys to define, access policy requirments)
3. Azure for Government subscription (duh)

## Rules Processed

Rules are processed and if a failure vent occurs, an event is logged in OMS for visiblity and processing.

1. Determines if any custom roles are defined within the reference (default) subscrption. (E.G. What custom roles should Azure Audit process, if none then issue alert)
2. Determines if defined custom roles are assigned to all subscriptions for a given Azure AD Tenant. (E.G. Ensures all custom roles associated with the reference subscription are also associated with all other Azure subscriptions within the AAD tenant.  If not, then issue alert)
3. Determines if a custom role has AAD identies associated with it's use. (E.G. John Doe is assigned to custom role X, if no one is assigned then issue alert)
4. [Future] Determines if resources of type Public IP Address are deployed within any Azure Subscrption, if yes then issue alert.
5. [Future] Determine if custom roles are assignments or definitions are modified from baseline, if yes then issue alert.
6. [Future] Determine if Azure route tables have been modified, if yes then issue alert.

---

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.