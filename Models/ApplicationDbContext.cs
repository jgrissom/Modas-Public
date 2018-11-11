using Microsoft.EntityFrameworkCore;

namespace Modas.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
        public DbSet<Event> Events { get; set; }
        public DbSet<Location> Locations { get; set; }
    }
}
