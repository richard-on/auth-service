package cookie

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// SetCookie sets cookie name and value for TTL seconds
func SetCookie(c *fiber.Ctx, name, value string, ttl int64) {
	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    value,
		Expires:  time.Now().Add(time.Second * time.Duration(ttl)).UTC(),
		HTTPOnly: true,
	})
}

// DeleteCookie deletes cookie by name
func DeleteCookie(c *fiber.Ctx, login string) {
	c.Cookie(&fiber.Cookie{
		Name:     login,
		Value:    "",
		Expires:  time.Unix(0, 0).UTC(),
		HTTPOnly: true,
	})
}
