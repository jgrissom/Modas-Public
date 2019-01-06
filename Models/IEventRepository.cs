using System.Linq;
using Microsoft.AspNetCore.JsonPatch;

namespace Modas.Models
{
    public interface IEventRepository
    {
        IQueryable<Event> Events { get; }
        IQueryable<Location> Locations { get; }

        Event AddEvent(Event evt);
        Event UpdateEvent(Event evt);
        void PatchEvent(int id, JsonPatchDocument<Event> patch);
        void DeleteEvent(int eventId);
    }
}
