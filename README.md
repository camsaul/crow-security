Crow Security
=============

Header-only HTTP Security Middleware for Crow.

    #include "crow.h"
    #include "contrib/security/SecurityMiddleware.h
    
    int main()
    {
        crow::Crow app;
        
        using namespace crow::security_middleware;
        using Type = Sources::Type;
        
        // Configure HTTP security headers when adding middleware; they'll be returned with every response
        app.use(new SecurityMiddleware()
                    .setXFrameOptions(XFrameOptions::DENY)
                    .setXSSProtection(XSSProtection::BLOCK)
                    .setNoSniff()
                    .setStrictTransportSecurity(31536000)
                    .setAccessControlAllowOrigin("http://mysite.com")
                    .setContentSecurityPolicy(Sources().trust(Type::DEFAULT, Sources::kSelf)
                                                       .trust(Type::FONT, "https://themes.googleusercontent.com"))
                    .setCrossDomainMetaPolicy(PermittedCrossDomainMetaPolicy::MASTER_ONLY));
    	
        CROW_ROUTE(app, "/")
        ([]{
            return "Hello World!";
        });
    
        CROW_MIDDLEWARE_USE(app, std::make_shared<crow_contrib::BasicAuth>("foo", "bar"));

        app.port(18080)
            .multithreaded()
            .run();
    }
