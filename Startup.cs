using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using OAuthProxy.Auth;
//using OidcApp.Auth;
using OidcApp.Models;
using OidcApp.Models.Entities;
using OidcApp.Models.Providers;
using OidcApp.Models.Repositories;

namespace OidcApp
{
    public class Startup
    {
        private const string SecretKey = "BlaBlaBlablaBLA123456743"; // todo: get this from somewhere secure
        private readonly SymmetricSecurityKey _signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SecretKey));

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var oidcProviders = new OidcProviders();
            Configuration.Bind("Oidc", oidcProviders);
            services.AddSingleton(oidcProviders);

            //TODO : finish the wire-up and combine JWT based and cookie based flows
            // jwt wire up
            // Get options from app settings
            //services.AddSingleton<IJwtFactory, JwtFactory>();
            //var jwtAppSettingOptions = Configuration.GetSection(nameof(JwtIssuerOptions));
            //// Configure JwtIssuerOptions
            //services.Configure<JwtIssuerOptions>(options =>
            //{
            //    options.Issuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
            //    options.Audience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)];
            //    options.SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);
            //});

            //var tokenValidationParameters = new TokenValidationParameters
            //{
            //    ValidateIssuer = true,
            //    ValidIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)],

            //    ValidateAudience = true,
            //    ValidAudience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)],

            //    ValidateIssuerSigningKey = true,
            //    IssuerSigningKey = _signingKey,

            //    RequireExpirationTime = false,
            //    ValidateLifetime = true,
            //    ClockSkew = TimeSpan.Zero
            //};

            JwtTokenCreatorConfig jwtTokenCreatorConfig = new JwtTokenCreatorConfig();
            Configuration.GetSection("JwtTokenCreatorConfig").Bind(jwtTokenCreatorConfig);
            services.AddSingleton(jwtTokenCreatorConfig);

            services.AddSingleton<JwtTokenCreator>();

            services.AddScoped<IUserRepo, UserRepo>();
            services.AddScoped<IUserManager, UserManager>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            var builder = services.AddAuthentication(options =>
            {
                //options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = SocialAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = SocialAuthenticationDefaults.AuthenticationScheme;
            }).AddJwtBearer(configureOptions =>
                {
                   // configureOptions.ClaimsIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                   // configureOptions.TokenValidationParameters = tokenValidationParameters;
                    configureOptions.SaveToken = true;
                })
            .AddCookie(SocialAuthenticationDefaults.AuthenticationScheme);

            foreach (OidcProvider provider in oidcProviders.Providers)
            {
                switch (provider.Name)
                {
                    case OidcProviderType.Google:
                        builder.AddGoogle(options =>
                        {
                            options.SaveTokens = true;
                            options.ClientId = provider.ClientId;
                            options.ClientSecret = provider.ClientSecret;
                            options.Events.OnTicketReceived = (context) =>
                            {
                                Console.WriteLine(context.HttpContext.User);
                                return Task.CompletedTask;
                            };
                            options.Events.OnCreatingTicket = (context) =>
                            {
                                Console.WriteLine(context.Identity);
                                return Task.CompletedTask;
                            };
                        });
                        break;
                    case OidcProviderType.Facebook:
                        builder.AddFacebook(options =>
                        {
                            options.SaveTokens = true;
                            options.ClientId = provider.ClientId;
                            options.ClientSecret = provider.ClientSecret;
                            options.Events.OnTicketReceived = (context) =>
                            {
                                Console.WriteLine(context.HttpContext.User);
                                return Task.CompletedTask;
                            };
                            options.Events.OnCreatingTicket = (context) =>
                            {
                                Console.WriteLine(context.Identity);
                                return Task.CompletedTask;
                            };
                        });
                        break;
                    case OidcProviderType.Microsoft:
                        builder.AddMicrosoftAccount(options =>
                       {
                           options.SaveTokens = true;
                           options.ClientId = provider.ClientId;
                           options.ClientSecret = provider.ClientSecret;
                           options.Events.OnTicketReceived = (context) =>
                           {
                               Console.WriteLine(context.HttpContext.User);
                               return Task.CompletedTask;
                           };
                           options.Events.OnCreatingTicket = (context) =>
                           {
                               Console.WriteLine(context.Identity);
                               return Task.CompletedTask;
                           };
                       });
                        break;
                }
            }

            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));
            });

            services.AddRouting(options => options.LowercaseUrls = true);

            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
