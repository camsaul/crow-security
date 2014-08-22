#pragma once

#include <unordered_map>
#include <boost/lexical_cast.hpp>
#include "crow.h"

namespace crow {
	namespace security_middleware {
		using Headers = std::unordered_map<std::string, std::string>;
		
		enum class XFrameOptions {
			DENY,			///< Don't allow site to be displayed in an iframe anywhere
			SAMEORIGIN,		///< Only allow site to be displayed in an iframe if page is from same origin
		};
		
		enum class XSSProtection {
			DISABLE,	///< Completely disable IE's built-in XSS Protection (X-XSS-Protection: 0)
			ENABLE,		///< Enable IE's built-in protection (X-XSS-Protection: 1)
			BLOCK		///< Completely block pages when suspected XSS is detected  (X-XSS-Protection: 1; mode=block)
		};
		
		/// Specify which origins are allowed to supply given content types. The default is the equivalent of "*" - any origin is allowed.
		class Sources {
		public:
			friend class SecurityMiddleware;
			
			/// Different resource types that can be set by Content-Security-Policy.
			/// Individual types are fine-grained, i.e. setting STYLE will not affect SCRIPT.
			enum class Type {
				DEFAULT,	///< specify default origins for ALL types that aren't specified.
				SCRIPT,		///< specify origins that can serve JavaScript
				STYLE,		///< specify origins that can server stylesheets
				CONNECT,	///< specify origins to which you can connect (via XHR, WebSockets, EventSource)
				FONT,		///< specify origins that can server web fonts (e.g. Google Web Fonts https://themes.googleusercontent.com)
				FRAME,		///< specify origins that can be embedded as frames
				IMG,		///< specify origins from which images can be loaded
				MEDIA,		///< specify origins that can deliver audio/video
				OBJECT,		///< specify origins that can deliver Flash and other plugins
			};
			
			static const std::string kSelf; ///< "'self'" for use as an origin.
			
			/// Trust this origin to supply the specified content type.
			Sources& trust(Type type, const std::string& origin = kSelf) {
				trustedSources_[type] += " " + origin; /// just combine matching types into single string
				return *this;
			}
		private:
			using TypeMap = std::unordered_map<Type, std::string>;
			static const TypeMap kTypeNames;
			TypeMap trustedSources_;
		};
		
		/// Flash/PDF files look for a file like "http://www.example.com/crossdomain.xml" at the root of your site so they can "ask permission"
		/// before including content from it. Specify whether only the master policy is allow or whether subfolders can have their own policies.
		enum class PermittedCrossDomainPolicy {
			NONE,				///< No policies are permitted anywhere on the server, not even this one
			MASTER_ONLY,		///< Only this master policy is allowed
			BY_CONTENT_TYPE,	///< Only policy files server wtih Content-Type: text/x-cross-domain-policy are allowed (HTTP/HTTPS Only)
			BY_FTP_FILENAME,	///< Only policy files whose names end in /crossdomain.xml are allowed (FTP Only)
			ALL					///< All policy files on this domain are allowed
		};
		
		/// Easy configuration of most of the import HTTP headers for securing a site.
		/// SecurityMiddleware uses a fluent API so you can easily chain settings
		/// \code
		/// SecurityMiddleware().setXFrameOptions(XFrameOptions::BLOCK).setNoSniff()
		/// \endcode
		class SecurityMiddleware : public IMiddleware {
		public:
#pragma mark - Create Instance
			/// Create a new SecurityMiddleware instance with some reasonable defaults.
			/// Intended just as a starting point - be sure to set up HSTS, Content Security Policy, etc.
			SecurityMiddleware() {
				setXFrameOptions(XFrameOptions::SAMEORIGIN)
				.setXSSProtection(XSSProtection::BLOCK)
				.setNoSniff();
			}
			
#pragma mark - X-Frame-Options
			/// Set the X-Frame-Options header to tell browsers not to render our site as an iframe in a different domain (prevent clickjacking)
			inline SecurityMiddleware& setXFrameOptions(XFrameOptions opts) {
				headers_["X-Frame-Options"] = opts == XFrameOptions::DENY ? "DENY" : "SAMEORIGIN";
				return *this;
			}
			
			/// Set X-Frame-Options to allow our site to be iframed by specified site.
			inline SecurityMiddleware& setXFrameOptionsAllowFrom(const std::string& origin) {
				headers_["X-Frame-Options"] = "ALLOW-FROM" + origin;
				return *this;
			}
			
#pragma mark - HTTP Strict Transport Security (HSTS)
			/// Tell browsers to use HTTPS by default; only allow the site to be accessed through HTTPS for specified interval """
			inline SecurityMiddleware& setStrictTransportSecurity(unsigned maxAgeInSeconds, bool includeSubdomains = true) {
				headers_["Strict-Transport-Security"] = "max-age=" + boost::lexical_cast<std::string>(maxAgeInSeconds) + "; " + (includeSubdomains ? "includeSubdomains" : "");
				return *this;
			}
			
#pragma mark - CORS
			/// Cross Object Resource Sharing (CORS) - allow cross-site HTTP requests from the specified origin. Don't set to "*" !
			inline SecurityMiddleware& setAccessControlAllowOrigin(const std::string& origin) {
				headers_["Access-Control-Allow-Origin"] = origin;
				return *this;
			}
			
#pragma mark - X-XSS-Protection
			
			
			/// Tell IE to be even more strict about how it responds to suspected XSS
			inline SecurityMiddleware& setXSSProtection(XSSProtection setting) {
				headers_["X-XSS-Protection"] = setting == XSSProtection::DISABLE ? "0" : setting == XSSProtection::ENABLE ? "1" : "1; mode=block";
				return *this;
			}
			
#pragma mark - Nosniff
			/// Nosniff - Tell IE not to try to use MIME-sniffing to guess the types of files
			inline SecurityMiddleware& setNoSniff(bool noSniff = true) {
				if (noSniff) {
					headers_["X-Content-Type-Options"] = "nosniff";
				} else {
					headers_.erase("X-Content-Type-Options");
				}
				return *this;
			}
			
#pragma mark - Content Security Policy
			/// Retrict which origins can deliver given content types. Result will look like "Content-Security-Policy: default-src 'self'; img-src 'self' http://google.com"
			inline SecurityMiddleware& setContentSecurityPolicy(Sources sources) {
				std::string value;
				for (auto pair : sources.trustedSources_) {
					if (!value.empty()) value += "; ";
					value += Sources::kTypeNames.at(pair.first) + pair.second;
				}
				headers_["Content-Security-Policy"] = value;
				return *this;
			}
			
#pragma mark - Cross Domain Meta Policy
			/// Prevent Flash / PDF Files from Including Content From Site
			inline SecurityMiddleware& setCrossDomainMetaPolicy(PermittedCrossDomainPolicy policy = PermittedCrossDomainPolicy::MASTER_ONLY) {
				using P = PermittedCrossDomainPolicy;
				headers_["X-Permitted-Cross-Domain-Policies"] =
				policy == P::NONE				? "none"			:
				policy == P::MASTER_ONLY		? "master-only"		:
				policy == P::BY_CONTENT_TYPE	? "by-content-type" :
				policy == P::BY_FTP_FILENAME	? "by-ftp-filename" :
				policy == P::ALL				? "all"				: "";
				return *this;
			}
			
			// TODO - Disable the 'Server: Crow/0.1' header
			
#pragma mark - Handle Request
			void after_handle(const request& req, response& res) {}
			
			void before_handle(const request& req, response& res) {
				for (auto pair : headers_) {
					res.headers[pair.first] = pair.second;
				}
				res.headers.erase("Server");
			}
			
		private:
			Headers headers_;
		};
		
		const Sources::TypeMap Sources::kTypeNames = {
			{Type::DEFAULT, "default-src"},
			{Type::SCRIPT,	"script-src"},
			{Type::STYLE,	"style-src"},
			{Type::CONNECT, "connect-src"},
			{Type::FONT,	"font-src"},
			{Type::FRAME,	"frame-src"},
			{Type::IMG,		"img-src"},
			{Type::MEDIA,	"media-src"},
			{Type::OBJECT,	"object-src"}
		};
		
		const std::string& Sources::kSelf = "'self'";
	}
}
