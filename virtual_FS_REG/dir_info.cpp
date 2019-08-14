#include "includes.h"


//////////////////////////////////////////////////////////////////////////
// See dirInfo.h for descriptions of the routines in this module.
//////////////////////////////////////////////////////////////////////////

// A comparison routine for std::sort that wraps PrjFileNameCompare() so that we can sort our DirInfo
// the same way the file system would.
bool file_name_less_than(const dir_entry& entry1, const dir_entry& entry2)
{
	return PrjFileNameCompare(entry1.file_name.c_str(), entry2.file_name.c_str()) < 0;
}

dir_info::dir_info(const PCWSTR file_path_name) :
	file_path_name(file_path_name),
	current_index(0),
	is_entries_filled(false)
{
}

void dir_info::reset()
{
	current_index = 0;
	is_entries_filled = false;
	entries_.clear();
}

bool dir_info::EntriesFilled() const
{
	return is_entries_filled;
}

bool dir_info::current_is_valid() const
{
	return current_index < entries_.size();
}

PRJ_FILE_BASIC_INFO dir_info::current_basic_info() const
{
	return entries_[current_index].basic_info;
}

PCWSTR dir_info::current_file_name() const
{
	return entries_[current_index].file_name.c_str();
}

bool dir_info::move_next()
{
	++current_index;

	return current_index < entries_.size();
}

size_t dir_info::get_current_index() const
{
	return current_index;
}

void dir_info::sort_entries_and_mark_filled()
{
	is_entries_filled = true;

	std::sort(entries_.begin(),
		entries_.end(),
		file_name_less_than);
}

void dir_info::fill_entry(const dir_entry& entry)
{
	entries_.emplace_back(entry);
}
