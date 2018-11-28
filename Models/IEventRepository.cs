using System.Linq;
namespace Modas.Models
{
    public interface IEventRepository
    {
        IQueryable<Event> Events { get; }
        IQueryable<Location> Locations { get; }

        Event AddEvent(Event evt);
        Event UpdateEvent(Event evt);
        void DeleteEvent(int eventId);
    }
}
