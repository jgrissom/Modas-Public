using System.Linq;

namespace Modas.Models
{
    public class EFEventRepository : IEventRepository
    {
        private ApplicationDbContext context;

        public EFEventRepository(ApplicationDbContext ctx)
        {
            context = ctx;
        }

        public IQueryable<Event> Events => context.Events;
        public IQueryable<Location> Locations => context.Locations;

        public Event AddEvent(Event evt)
        {
            context.Add(evt);
            context.SaveChanges();
            return evt;
        }

        public Event UpdateEvent(Event evt)
        {
            Event Event = context.Events.FirstOrDefault(e => e.EventId == evt.EventId);
            Event.TimeStamp = evt.TimeStamp;
            Event.Flagged = evt.Flagged;
            Event.LocationId = evt.LocationId;
            context.SaveChanges();
            return Event;
        }

        public void DeleteEvent(int eventId)
        {
            Event evt = context.Events.FirstOrDefault(e => e.EventId == eventId);
            context.Events.Remove(evt);
            context.SaveChanges();
        }
    }
}
