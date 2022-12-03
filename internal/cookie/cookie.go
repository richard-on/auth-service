package cookie

import (
	"github.com/richard-on/auth-service/config"
	"time"

	"github.com/gofiber/fiber/v2"
)

// SetCookie sets cookie name and value for TTL seconds
func SetCookie(c *fiber.Ctx, name, value string, ttl int64) {
	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    value,
		Domain:   config.Host,
		MaxAge:   int(ttl),
		Expires:  time.Now().Add(time.Second * time.Duration(ttl)).UTC(),
		Secure:   config.SecureCookie,
		HTTPOnly: true,
		SameSite: "Lax",
	})
}

// DeleteCookie deletes cookie by name
func DeleteCookie(c *fiber.Ctx, name string) {
	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    "",
		Domain:   config.Host,
		MaxAge:   0,
		Expires:  time.Unix(0, 0).UTC(),
		Secure:   config.SecureCookie,
		HTTPOnly: true,
		SameSite: "Lax",
	})
}
