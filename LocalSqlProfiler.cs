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

        //WhoAmI?
        public string ProfilerSource => "LOCAL";

        /// <summary>
        /// Add defaults to the Photon configuration HotState and EAV if they are missing.
        /// </summary>
        public async Task ProcessConfig()
        {
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

            // Activated? Don't turn this one off if everything else is off... that would mean no one can log in to the system at all!
            if (!await Config.System<bool>($"IdentityProviders.Local.Acivated"))
            {
                Console.Write(">>> [LOCAL SQL IDENTITY PROVIDER] Disabled"); //Photon grabs these and logs them but also shows this on startup. This will not stop the gateway from starting up.
                return new IdentityProfileResult { IsSuccess = false };
            }

            // Get the Globals.PrimaryDispatcher to execute. Provides connection and telemetry.
            var _dispatcher = Globals.PrimaryDispatcher;
            var userRecord = await _dispatcher.QueryFirstOrDefaultAsync<TableModel_Auth>(@"SELECT UserId, Password, EmailAddress, DisplayName FROM {prefix}Auth WHERE UserName = @u AND Enabled = 1", new { u = username });
            
            // Return the result back as IdentityProfileResult if it validates
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

            // return this if nothing is found
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
            //Compare the input and against the hashed to get a match. Depending on the config, this could be salted -or- someone changeed the algorithm or salt to force password changes.
            return Security.Cryptography.HashPassword(input).ToUpper() == hashed.ToUpper();
        }
    }
}

