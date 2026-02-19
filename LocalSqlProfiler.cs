using Microsoft.Extensions.Configuration;
using Photon.Core.Configuration;
using Photon.Core.Database.Deployment.Models.Tables;

namespace Photon.Core.Identity.Providers
{


    /// <summary>
    /// Default Local SQL Identity Provider for Local Photon Accounts
    /// </summary>
    /// <param name="config"></param>
    public class LocalSqlProfiler(IConfiguration config) : IIdentityProfiler
    {

        public string ProfilerSource => "LOCAL";

        public async Task ProcessConfig()
        {
            // Summary of function: Seeding News module defaults.
            // Remarks: Runs via reflection during Gateway ignition.
            //await Config.System<int>($"{PluginName}.MaxToShowFirst", 5);
            Console.Write(">>> [LOCAL SQL IDENTITY PROVIDER] Loaded");
            await ConfigurationManager<object>.SetDefaultData<bool>($"IdentityProviders.Local.Acivated", true, "Enable the local SQL provider. If no other identity provider is enabled and this is disabled, no one will be able to log into the gateway.");
        }

        /// <summary>
        /// Authenticate against provider
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns>PhotonProfileResult collection</returns>
        public async Task<IdentityProfileResult> AuthenticateAsync(string username, string password)
        {

            // Activated? Don't turn this one off if everything else is off... that would mean no one can log in to the system at all
            if (!await Config.System<bool>($"IdentityProviders.Local.Acivated"))
            {
                Console.Write(">>> [LOCAL SQL IDENTITY PROVIDER] Disabled");
                return new IdentityProfileResult { IsSuccess = false };
            }

            // Instantate the connection using the gateway Public Dispatcher ISqlDispatcher found in Globals
            // well use QueryFirstOrDefaultAsync with TableModel_Auth to align username and appsword
            var _dispatcher = Globals.PrimaryDispatcher;

            var userRecord = await _dispatcher.QueryFirstOrDefaultAsync<TableModel_Auth>(@"SELECT UserId, Password, EmailAddress, DisplayName FROM {prefix}Auth WHERE UserName = @u AND Enabled = 1", new { u = username });

            if (userRecord != null && VerifyPassword(password, userRecord.Password))
            {
                return new IdentityProfileResult
                {
                    IsSuccess = true,
                    UserId = (int)userRecord.UserId,
                    Username = username,
                    Email = userRecord.EmailAddress,
                    DisplayName = userRecord.DisplayName
                };
            }
            return new IdentityProfileResult { IsSuccess = false };
        }

        /// <summary>
        /// Return password comparison result
        /// </summary>
        /// <param name="input"></param>
        /// <param name="hashed"></param>
        /// <returns></returns>
        private bool VerifyPassword(string input, string hashed)
        {
            return Security.Cryptography.HashPassword(input).ToUpper() == hashed.ToUpper();
        }
    }
}
