using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.JsonPatch;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Modas.Models;
using Modas.Models.ViewModels;

namespace Modas.Controllers
{
    [Route("api/[controller]")]
    public class EventController : Controller
    {
        private readonly int PageSize = 20;
        private IEventRepository repository;
        public EventController(IEventRepository repo) => repository = repo;

        [HttpGet, Authorize]
        // returns all events (unsorted)
        public IEnumerable<Event> Get() => repository.Events
            .Include(e => e.Location);

        [HttpGet]
        [Route("count")]
        public int GetCount() => repository.Events.Count();

        [HttpGet("page{page:int}")]
        // returns all events by page
        public ApiListViewModel GetPage(int page = 1) =>
            new ApiListViewModel
            {
                Events = repository.Events
                    .Select(e => new ApiViewEvent
                    {
                        EventId = e.EventId,
                        Flagged = e.Flagged,
                        TimeStamp = e.TimeStamp,
                        LocationName = e.Location.Name
                    })
                    .OrderByDescending(e => e.TimeStamp)
                    .Skip((page - 1) * PageSize)
                    .Take(PageSize),
                PagingInfo = new PagingInfo
                {
                    CurrentPage = page,
                    ItemsPerPage = PageSize,
                    TotalItems = repository.Events.Count()
                }
            };

        [HttpGet("{id}")]
        // return specific event
        public Event Get(int id) => repository.Events
            .Include(e => e.Location)
            .FirstOrDefault(e => e.EventId == id);

        [HttpPost]
        // add event
        public Event Post([FromBody] Event evt) => repository.AddEvent(new Event
        {
            TimeStamp = evt.TimeStamp,
            Flagged = evt.Flagged,
            LocationId = evt.LocationId
        });

        [HttpPut]
        // update event
        public Event Put([FromBody] Event evt) => repository.UpdateEvent(evt);

        [HttpPatch("{id}")]
        // update event (specific fields)
        public void Patch(int id, [FromBody]JsonPatchDocument<Event> patch) => repository.PatchEvent(id, patch);

        [HttpDelete("{id}")]
        // delete event
        public void Delete(int id) => repository.DeleteEvent(id);
    }
}
