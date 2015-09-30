#include "SecurityMiddleware.h"

namespace crow {
	namespace security_middleware {
		
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
		
		const std::string Sources::kSelf = "'self'";

		Sources& Sources::trust(Type type, const std::string& origin) {
			trustedSources_[type] += " " + origin; /// just combine matching types into single string
			return *this;
		}
		
		SecurityMiddleware::SecurityMiddleware() {
			setXFrameOptions(XFrameOptions::SAMEORIGIN)
			.setXSSProtection(XSSProtection::BLOCK)
			.setNoSniff();
		}
		
		void SecurityMiddleware::after_handle(const request& req, response& res, context& ctx) {
			res.set_header("Server", "");
		}
		
		void SecurityMiddleware::before_handle(const request& req, response& res, context& ctx) {
			for (auto pair : headers_) {
				res.add_header(pair.first, pair.second);
			}
		}
	}
}
