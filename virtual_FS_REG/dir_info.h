#pragma once


struct dir_entry
{
	std::wstring file_name{};
	PRJ_FILE_BASIC_INFO basic_info{};
};


class dir_info
{
public:

	// Constructs a new empty DirInfo, initializing it with the name of the directory it represents.
	explicit dir_info(PCWSTR file_path_name);

	// Sorts the entries in the DirInfo object and marks the object as being fully populated.
	void sort_entries_and_mark_filled();

	void fill_entry(const dir_entry& entry);

	// Returns true if the DirInfo object has been populated with entries.
	[[nodiscard]] bool EntriesFilled() const;

	// Returns true if CurrentBasicInfo() and current_file_name() will return valid values. 
	[[nodiscard]] bool current_is_valid() const;

	// Returns a PRJ_FILE_BASIC_INFO populated with the information for the current item.
	[[nodiscard]] PRJ_FILE_BASIC_INFO current_basic_info() const;

	// Returns the file name for the current item.
	[[nodiscard]] PCWSTR current_file_name() const;

	// Moves the internal index to the next DirEntry item.  Returns false if there are no more items.
	bool move_next();

	[[nodiscard]] size_t get_current_index() const;

	// Deletes all the DirEntry items in the DirInfo object.
	void reset();

	//private:

	// Stores the name of the directory this DirInfo represents.
	std::wstring file_path_name{};

	// The index of the item in _entries that CurrentBasicInfo() and current_file_name() will return.
	std::atomic<size_t> current_index;

	// Marks whether or not this DirInfo has been filled with entries.
	std::atomic<bool> is_entries_filled;

	// The list of entries in the directory this DirInfo represents.
	std::vector<dir_entry> entries_;
};
