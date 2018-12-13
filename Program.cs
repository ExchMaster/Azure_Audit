using System;
using System.Threading.Tasks;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Management.Graph.RBAC.Fluent;

namespace Azure_Audit
{
    public class defInfo
    {

        public string defName;
        public string defGUID;
        public bool isAssigned = false;

    }
    delegate void asyncDelegate(string[] srvPrinCreds);

    class Program
    {
        struct subDefinitions
        {
            public string roleName;
            public string subName;
            public string subID;
            public IList<string> actions;
            public IList<string> notActions;
            public IList<string> dataActions;
            public IList<string> notDataActions;
            public subDefinitions(string roleName, string subName, string subID, IList<string> actions, IList<string> notActions, IList<string> dataActions, IList<string> notDataActions)
            {
                this.roleName = roleName;
                this.subName = subName;
                this.subID = subID;
                this.actions = actions;
                this.notActions = notActions;
                this.dataActions = dataActions;
                this.notDataActions = notDataActions;
            }
        }
        // An example JSON object, with key/value pairs
        //static string json = @"[{""DemoField1"":""ForReal"",""DemoField2"":""DemoValue2""},{""DemoField3"":""DemoValue3"",""DemoField4"":""DemoValue4""}]";
        static string json = "[{\"Field1\":\"Value1\",\"Field2\":\"Value2\"},{\"Field3\":\"Value3\",\"Field4\":\"Value4\"}]";

        // LogName is name of the event type that is being submitted to Log Analytics
        static string LogName = "Azure_Audit";

        // You can use an optional field to specify the timestamp from the data. If the time field is not specified, Log Analytics assumes the time is the message ingestion time
        static string TimeStampField = "datestring";

        public static string BuildSignature(string message, string secret)
        {
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = Convert.FromBase64String(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hash = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hash);
            }
        }
        public static void prepForOMS(string json, string customerId, string sharedKey)
        {
            //var datestring = DateTime.UtcNow.ToLocalTime().ToString("r");
            var datestring = DateTime.UtcNow.ToString("r");
            var jsonBytes = Encoding.UTF8.GetBytes(json);
            string stringToHash = "POST\n" + jsonBytes.Length + "\napplication/json\n" + "x-ms-date:" + datestring + "\n/api/logs";
            string hashedString = BuildSignature(stringToHash, sharedKey);
            string signature = "SharedKey " + customerId + ":" + hashedString;
            PostData(signature, datestring, json, customerId);

        }
        public static void PostData(string signature, string date, string json, string customerId)
        {
            try
            {
                string url = "https://" + customerId + ".ods.opinsights.azure.us/api/logs?api-version=2016-04-01";

                System.Net.Http.HttpClient client = new System.Net.Http.HttpClient();
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                client.DefaultRequestHeaders.Add("Log-Type", LogName);
                client.DefaultRequestHeaders.Add("Authorization", signature);
                client.DefaultRequestHeaders.Add("x-ms-date", date);
                client.DefaultRequestHeaders.Add("time-generated-field", TimeStampField);

                System.Net.Http.HttpContent httpContent = new StringContent(json, Encoding.UTF8);
                httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                Task<System.Net.Http.HttpResponseMessage> response = client.PostAsync(new Uri(url), httpContent);

                int responseContent = (int)response.Result.StatusCode;
                Console.WriteLine("Return Result (HTTP Status Code): " + responseContent);

            }
            catch (Exception excep)
            {
                Console.WriteLine("API Post Exception: " + excep.Message);
            }
        }
        private static string[] GetSecretFromKeyVault(AzureServiceTokenProvider azureServiceTokenProvider, string keyVaultName)
        {
            string srvprinappID = "appID";
            string srvprinkey = "key";
            string srvprindefaultSubscription = "defaultSubscription";
            string srvprintenantID = "tenantID";
            string omsCustomerID = "omsID";
            string omsKey = "omsKey";

            string[] arrCreds = new string[] { srvprinappID, srvprinkey, srvprindefaultSubscription, srvprintenantID, omsCustomerID, omsKey };

            KeyVaultClient kv = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            try
            {
                for (int i = 0; i < 6; i++)
                {
                    var secret = kv
                        .GetSecretAsync($"https://{keyVaultName}.vault.usgovcloudapi.net/secrets/{arrCreds[i]}").Result;

                    arrCreds[i] = secret.Value;
                }

            }
            catch (Exception exp)
            {
                Console.WriteLine($"Something went wrong: {exp.Message}");
            }
            return arrCreds;
        }

        public static void processRBACRules(string[] srvPrinCreds)
        {
            //"While" loop necessary for continuous container deployments on Windows & Linux.
            //Not needed for Function App because function app executes on a timed trigger inherent to the platform

            List<defInfo> defsInfo = new List<defInfo>();

            IAzure[] getAzureCreds(int subCount, AzureCredentials azureCreds, List<ISubscription> subIDList)
            {
                IAzure[] azAuthCreds = new Azure[subCount];
                int getAzureCredsIndex = 0;
                foreach (var sub in subIDList)
                {
                    string sid = sub.SubscriptionId;
                    azAuthCreds[getAzureCredsIndex] = Azure
                        .Configure()
                        .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                        .Authenticate(azureCreds)
                        .WithSubscription(sub.SubscriptionId);
                    getAzureCredsIndex++;
                }

                return azAuthCreds;
            }

            var credentials = SdkContext.AzureCredentialsFactory
                .FromServicePrincipal(srvPrinCreds[0], srvPrinCreds[1], srvPrinCreds[3], AzureEnvironment.AzureUSGovernment)
                .WithDefaultSubscription(srvPrinCreds[2]);
            //.FromFile(Environment.GetEnvironmentVariable("AZURE_AUTH_LOCATION"));

            var azure = Azure
                .Configure()
                .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                .Authenticate(credentials)
                .WithSubscription(credentials.DefaultSubscriptionId);


            var subList = azure.Subscriptions.List().ToList();
            int subListCount = subList.Count - 1;
            string refSubID = "<refSubIDGUID>";
            string refSubName = "<refSubName>";
            string refSubFullyQualifiedID = "<refSubFullyQualifiedID";
            List<string> sortedSubFQIDs = new List<string>();
            List<string> refSubFQIDs = new List<string>();
            foreach (var sub in subList)
            {
                if (sub.SubscriptionId == credentials.DefaultSubscriptionId)
                {
                    refSubID = sub.SubscriptionId;
                    refSubName = sub.DisplayName;
                    refSubFullyQualifiedID = sub.Inner.Id;
                }
                //Grab fully qualified sub ID's that our srv principle has access too
                refSubFQIDs.Add(sub.Inner.Id);
            }
            //Sort our list of fully qualified sub ID's for comparison later
            refSubFQIDs.Sort();

            //Get reference subscription role definitions: name,assignable scopes

            var refSubRDefs = azure.AccessManagement.RoleDefinitions.ListByScope(refSubFullyQualifiedID);
            //Determine count of custom role definitions for reference subscription
            int refSubDefCount = 0;

            foreach (var rDefinition in refSubRDefs)
            {
                if (rDefinition.Inner.RoleType.ToLower() != "builtinrole")
                {
                    refSubDefCount++;
                    defInfo def = new defInfo();
                    def.defName = rDefinition.RoleName;
                    def.defGUID = rDefinition.Name;
                    defsInfo.Add(def);
                    List<string> refSubDefScopes = new List<string>();
                    foreach (var scope in rDefinition.AssignableScopes)
                    {
                        refSubDefScopes.Add(scope);
                    }
                    refSubDefScopes.Sort();
                    //If role definition scope does not contain all tenant subscriptions then post to oms
                    if (!refSubFQIDs.SequenceEqual(refSubDefScopes))
                    {
                        json = $"[{{\"Category\":\"Warning\",\"Tenant ID: \":\"{credentials.TenantId}\",\"RBAC Custom Role Name\":\"{rDefinition.RoleName}\",\"Description\":\"Role definition scope does not include all accessible tenant subscriptions.  This role will not be avaliable for assignment for all missing subscriptions.\",\"Resolution URI\":\"https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles-powershell\"}}]";
                        prepForOMS(json, srvPrinCreds[4], srvPrinCreds[5]);
                    }
                }

            }
            if (refSubDefCount == 0)
            {
                refSubDefCount = -1;
                json = $"[{{\"Category\":\"Warning\",\"Reference Subscription Name\":\"{azure.GetCurrentSubscription().DisplayName}\",\"Reference Subscription ID\":\"{azure.SubscriptionId}\",\"Description\":\"Reference subcription does not have any custom roles defined\",\"Resolution URI\":\"https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles-powershell\"}}]";
                prepForOMS(json, srvPrinCreds[4], srvPrinCreds[5]);
            }
            var removeRefSub = subList.Single(r => r.SubscriptionId == refSubID);
            subList.Remove(removeRefSub);


            IAzure[] creds = getAzureCreds(subCount: subListCount, azureCreds: credentials, subIDList: subList);

            foreach (var cred in creds)
            {

                IEnumerable<IRoleAssignment> rAssign = azure.AccessManagement.RoleAssignments.ListByScope($"/subscriptions/{cred.SubscriptionId}");

                //Check whether or not each custom role defintion is assigned in current subscription
                foreach (var assignment in rAssign)
                {
                    var rdefID = assignment.RoleDefinitionId.Split("/");
                    var isAssigned = defsInfo.SingleOrDefault(r => r.defGUID == rdefID.Last());
                    if (isAssigned != null)
                    {
                        isAssigned.isAssigned = true;
                    }
                }
                //Find all unassigned roles and submit to OMS
                var unassignedRoles = defsInfo.Where(r => r.isAssigned == false);
                foreach (var unassignedRole in unassignedRoles)
                {
                    json = $"[{{\"Category\":\"Warning\",\"Subscription Name\":\"{cred.GetCurrentSubscription().DisplayName}\",\"Subscription ID\":\"{cred.SubscriptionId}\",\"Unassigned Role Name\":\"{unassignedRole.defName}\",\"Description\":\"Custom role '{unassignedRole.defName}' has been defined, but is not assigned in subscription '{cred.SubscriptionId}'\",\"Resolution URI\":\"https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles-powershell\"}}]";
                    prepForOMS(json, srvPrinCreds[4], srvPrinCreds[5]);
                }
                //Reset defintion state so that the next subscription can be processed
                foreach (var def in defsInfo)
                {
                    def.isAssigned = false;
                }

            }


        }
        static void Main(string[] args)
        {
            string[] srvPrinCreds = new string[6];
            string keyVaultName = System.Environment.GetEnvironmentVariable("keyVaultName");
            AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();

            srvPrinCreds = GetSecretFromKeyVault(azureServiceTokenProvider, keyVaultName);

            //Begin rule processing
            while (true)
            {
                //Add function for rules processing here
                processRBACRules(srvPrinCreds);
                //processResourceTypeRules(srvPrinCreds);
                //processAzureActivityRules(srvPrinCreds);
                System.Threading.Thread.Sleep(300001);
            }
        }
    }
}

